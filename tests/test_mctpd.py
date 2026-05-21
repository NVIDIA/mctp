import pytest
import trio
import asyncdbus

from mctp_test_utils import (
    mctpd_mctp_iface_obj,
    mctpd_mctp_network_obj,
    mctpd_mctp_endpoint_common_obj,
    mctpd_mctp_endpoint_control_obj,
    mctpd_service_readiness_obj,
    mctpd_mctp_base_iface_obj,
)
from mctpenv import Endpoint, MCTPSockAddr, MCTPControlCommand, MctpdWrapper

# DBus constant symbol suffixes:
#
# - C: Connection
# - P: Path
# - I: Interface
MCTPD_C = 'au.com.codeconstruct.MCTP1'
MCTPD_MCTP_P = '/au/com/codeconstruct/mctp1'
MCTPD_MCTP_I = 'au.com.codeconstruct.MCTP.BusOwner1'
MCTPD_ENDPOINT_I = 'au.com.codeconstruct.MCTP.Endpoint1'
MCTPD_ENDPOINT_BRIDGE_I = 'au.com.codeconstruct.MCTP.Bridge1'
DBUS_OBJECT_MANAGER_I = 'org.freedesktop.DBus.ObjectManager'
DBUS_PROPERTIES_I = 'org.freedesktop.DBus.Properties'

# Service readiness interface constants
OPENBMC_SERVICE_READINESS_I = 'xyz.openbmc_project.State.ServiceReady'
SERVICE_STATE_STARTING = 'xyz.openbmc_project.State.ServiceReady.States.Starting'
SERVICE_STATE_ENABLED = 'xyz.openbmc_project.State.ServiceReady.States.Enabled'
SERVICE_TYPE_MCTP = 'xyz.openbmc_project.State.ServiceReady.ServiceTypes.MCTP'

MCTPD_TRECLAIM = 5


async def _introspect_path_recursive(dbus, path, node_set):
    node_set.add(path)
    dups = set()

    obj = await dbus.get_proxy_object('au.com.codeconstruct.MCTP1', path)
    iface = await obj.get_interface('org.freedesktop.DBus.Introspectable')
    data = await iface.call_introspect()
    node = asyncdbus.introspection.Node.parse(data)

    for subnode in node.nodes:
        if path == '/':
            subnode_path = '/' + subnode.name
        else:
            subnode_path = path + '/' + subnode.name

        if subnode_path in node_set:
            dups.add(subnode_path)

        d = await _introspect_path_recursive(dbus, subnode_path, node_set)
        dups.update(d)

    return dups


async def test_enumerate(dbus, mctpd):
    """Test that the dbus object tree is sensible: we can introspect all
    objects, and that there are no duplicates
    """
    dups = await _introspect_path_recursive(dbus, '/', set())
    assert not dups


async def test_setup_endpoint(dbus, mctpd):
    """Test the SetupEndpoint dbus call

    Using the default system & network ojects, call SetupEndpoint on our mock
    endpoint. We expect the dbus call to return the endpoint details, and
    the new kernel neighbour and route entries.

    We have a few things provided by the test infrastructure:

     - dbus is the dbus connection, call the mctpd_mctp_iface_obj helper to
       get the MCTP dbus interface object

     - mctpd is our wrapper for the mctpd process and mock MCTP environment.
       This has two properties that represent external state:

       mctp.system: the local system info - containing MCTP interfaces
       (mctp.system.interfaces), addresses (.addresses), neighbours
       (.neighbours) and routes (.routes). These may be updated by the running
       mctpd process during tests, over the simlated netlink socket.

       mctp.network: the set of remote MCTP endpoints connected to the system.
       Each endpoint has a physical address (.lladdr) and an EID (.eid), and a
       tiny MCTP control protocol implementation, which the mctpd process will
       interact with over simulated AF_MCTP sockets.

    By default, we get some minimal defaults for .system and .network:

     - The system has one interface ('mctp0'), assigned local EID 8. This is
       similar to a MCTP-over-i2c interface, in that physical addresses are
       a single byte.

     - The network has one endpoint (lladdr 0x1d) connected to mctp0, with no
       EID assigned. It also has a random UUID, and advertises support for MCTP
       Control Protocol and PLDM (but note that it doesn't actually implement
       any PLDM!).

    But these are only defaults; .system and .network can be altered as
    required for each test.
    """
    # shortcuts to the default system/network configuration
    iface = mctpd.system.interfaces[0]
    ep = mctpd.network.endpoints[0]

    # our proxy dbus object for mctpd
    mctp = await mctpd_mctp_iface_obj(dbus, iface)

    # call SetupEndpoint. This will raise an exception on any dbus error.
    (eid, net, path, new) = await mctp.call_setup_endpoint(ep.lladdr)

    # ep.eid will be updated (through the Set Endpoint ID message); this
    # should match the returned EID
    assert eid == ep.eid

    # we should have a neighbour for the new endpoint
    assert len(mctpd.system.neighbours) == 1
    neigh = mctpd.system.neighbours[0]
    assert neigh.lladdr == ep.lladdr
    assert neigh.eid == ep.eid

    # we should have a route for the new endpoint too
    assert len(mctpd.system.routes) == 2


async def test_setup_endpoint_conflict(dbus, mctpd):
    """Test that we correctly handle address conflicts on EID assignment.

    We have the following scenario:

     1. A configured peer at physaddr 1, EID A, allocated by mctpd
     2. A non-configured peer at physaddr 2, somehow carrying a default EID
        also A
     3. Attempt to enumerate physaddr 2

    At (3), we should reconfigure the EID to B.
    """
    iface = mctpd.system.interfaces[0]

    mctp = await mctpd_mctp_iface_obj(dbus, iface)

    ep1 = mctpd.network.endpoints[0]
    (eid1, _, _, _) = await mctp.call_setup_endpoint(ep1.lladdr)

    # endpoint configured with eid1 already
    ep2 = Endpoint(iface, bytes([0x1E]), eid=eid1)
    mctpd.network.add_endpoint(ep2)

    (eid2, _, _, _) = await mctp.call_setup_endpoint(ep2.lladdr)
    assert eid1 != eid2


async def test_remove_endpoint(dbus, mctpd):
    """Test neighbour removal"""
    iface = mctpd.system.interfaces[0]
    ep1 = mctpd.network.endpoints[0]

    mctp = await mctpd_mctp_iface_obj(dbus, iface)
    (_, _, path, _) = await mctp.call_setup_endpoint(ep1.lladdr)

    assert len(mctpd.system.neighbours) == 1

    ep = await mctpd_mctp_endpoint_control_obj(dbus, path)

    await ep.call_remove()
    assert len(mctpd.system.neighbours) == 0


async def test_recover_endpoint_present(dbus, mctpd):
    iface = mctpd.system.interfaces[0]
    dev = mctpd.network.endpoints[0]
    mctp = await mctpd_mctp_iface_obj(dbus, iface)
    (eid, net, path, new) = await mctp.call_setup_endpoint(dev.lladdr)

    ep = await dbus.get_proxy_object(MCTPD_C, path)
    ep_props = await ep.get_interface(DBUS_PROPERTIES_I)

    recovered = trio.Semaphore(initial_value=0)

    def ep_connectivity_changed(iface, changed, invalidated):
        if iface == MCTPD_ENDPOINT_I and 'Connectivity' in changed:
            if 'Available' == changed['Connectivity'].value:
                recovered.release()

    await ep_props.on_properties_changed(ep_connectivity_changed)

    ep_ep = await ep.get_interface(MCTPD_ENDPOINT_I)
    await ep_ep.call_recover()

    with trio.move_on_after(2 * MCTPD_TRECLAIM) as expected:
        await recovered.acquire()

    # Cancellation implies failure to acquire recovered, which implies failure
    # to transition 'Connectivity' to 'Available', which is a test failure.
    assert not expected.cancelled_caught


async def test_recover_endpoint_removed(dbus, mctpd, autojump_clock):
    iface = mctpd.system.interfaces[0]
    dev = mctpd.network.endpoints[0]
    mctp = await dbus.get_proxy_object(MCTPD_C, MCTPD_MCTP_P)
    mctp_iface = await mctpd_mctp_iface_obj(dbus, iface)
    (eid, net, path, new) = await mctp_iface.call_setup_endpoint(dev.lladdr)

    ep = await dbus.get_proxy_object(MCTPD_C, path)
    ep_props = await ep.get_interface(DBUS_PROPERTIES_I)

    degraded = trio.Semaphore(initial_value=0)

    def ep_connectivity_changed(iface, changed, invalidated):
        if iface == MCTPD_ENDPOINT_I and 'Connectivity' in changed:
            if 'Degraded' == changed['Connectivity'].value:
                degraded.release()

    await ep_props.on_properties_changed(ep_connectivity_changed)

    mctp_objmgr = await mctp.get_interface(DBUS_OBJECT_MANAGER_I)

    removed = trio.Semaphore(initial_value=0)

    def ep_removed(ep_path, interfaces):
        if ep_path == path and MCTPD_ENDPOINT_I in interfaces:
            removed.release()

    await mctp_objmgr.on_interfaces_removed(ep_removed)

    del mctpd.network.endpoints[0]
    ep_ep = await ep.get_interface(MCTPD_ENDPOINT_I)
    await ep_ep.call_recover()

    with trio.move_on_after(2 * MCTPD_TRECLAIM) as expected:
        await removed.acquire()
        await degraded.acquire()

    assert not expected.cancelled_caught


async def test_recover_endpoint_reset(dbus, mctpd, autojump_clock):
    iface = mctpd.system.interfaces[0]
    dev = mctpd.network.endpoints[0]
    mctp_iface = await mctpd_mctp_iface_obj(dbus, iface)
    (eid, net, path, new) = await mctp_iface.call_setup_endpoint(dev.lladdr)

    ep = await dbus.get_proxy_object(MCTPD_C, path)
    ep_props = await ep.get_interface(DBUS_PROPERTIES_I)

    recovered = trio.Semaphore(initial_value=0)

    def ep_connectivity_changed(iface, changed, invalidated):
        if iface == MCTPD_ENDPOINT_I and 'Connectivity' in changed:
            if 'Available' == changed['Connectivity'].value:
                recovered.release()

    await ep_props.on_properties_changed(ep_connectivity_changed)

    # Disable the endpoint device
    del mctpd.network.endpoints[0]

    ep_ep = await ep.get_interface(MCTPD_ENDPOINT_I)
    await ep_ep.call_recover()

    # Force the first poll to fail
    await trio.sleep(1)

    # Reset the endpoint device and re-enable it
    dev.reset()
    dev.eid = eid
    mctpd.network.add_endpoint(dev)

    with trio.move_on_after(2 * MCTPD_TRECLAIM) as expected:
        await recovered.acquire()

    assert not expected.cancelled_caught


async def test_recover_endpoint_exchange(dbus, mctpd, autojump_clock):
    iface = mctpd.system.interfaces[0]
    dev = mctpd.network.endpoints[0]
    mctp = await dbus.get_proxy_object(MCTPD_C, MCTPD_MCTP_P)
    mctp_iface = await mctpd_mctp_iface_obj(dbus, iface)
    (eid, net, path, new) = await mctp_iface.call_setup_endpoint(dev.lladdr)

    ep = await dbus.get_proxy_object(MCTPD_C, path)
    ep_props = await ep.get_interface(DBUS_PROPERTIES_I)

    degraded = trio.Semaphore(initial_value=0)

    def ep_connectivity_changed(iface, changed, invalidated):
        if iface == MCTPD_ENDPOINT_I and 'Connectivity' in changed:
            if 'Degraded' == changed['Connectivity'].value:
                degraded.release()

    await ep_props.on_properties_changed(ep_connectivity_changed)

    mctp_objmgr = await mctp.get_interface(DBUS_OBJECT_MANAGER_I)

    removed = trio.Semaphore(initial_value=0)

    def ep_removed(ep_path, interfaces):
        if ep_path == path and MCTPD_ENDPOINT_I in interfaces:
            removed.release()

    await mctp_objmgr.on_interfaces_removed(ep_removed)

    added = trio.Semaphore(initial_value=0)

    def ep_added(ep_path, content):
        if MCTPD_ENDPOINT_I in content:
            added.release()

    await mctp_objmgr.on_interfaces_added(ep_added)

    # Remove the current device
    del mctpd.network.endpoints[0]

    ep_ep = await ep.get_interface(MCTPD_ENDPOINT_I)
    await ep_ep.call_recover()

    # Force the first poll to fail
    await trio.sleep(1)

    # Add a new the endpoint device at the same physical address (different UUID)
    mctpd.network.add_endpoint(Endpoint(dev.iface, dev.lladdr, types=dev.types))

    with trio.move_on_after(2 * MCTPD_TRECLAIM) as expected:
        await added.acquire()
        await removed.acquire()
        await degraded.acquire()

    assert not expected.cancelled_caught


async def test_assign_endpoint_static(dbus, mctpd):
    """Test that we get the correct EID allocated (and the usual route/neigh
    setup) on an AssignEndpointStatic call
    """
    iface = mctpd.system.interfaces[0]
    dev = mctpd.network.endpoints[0]
    mctp = await mctpd_mctp_iface_obj(dbus, iface)
    static_eid = 12
    start_eid = 13
    ignore_eids = b''  # Empty array - no EIDs to ignore
    ignore_message_types = b''  # Empty array - no Message types to ignore

    (eid, _, _, new) = await mctp.call_assign_endpoint_static(
        dev.lladdr,
        static_eid,
        start_eid,
        ignore_eids,
        ignore_message_types
    )

    assert eid == static_eid
    assert new

    assert len(mctpd.system.neighbours) == 1
    neigh = mctpd.system.neighbours[0]
    assert neigh.lladdr == dev.lladdr
    assert neigh.eid == static_eid
    assert len(mctpd.system.routes) == 2


async def test_recover_endpoint_without_uuid_keeps_eid(dbus, mctpd):
    class NoUuidEndpoint(Endpoint):
        async def handle_mctp_control(self, sock, src_addr, msg):
            flags, opcode = msg[0:2]
            if opcode != 3:
                return await super().handle_mctp_control(sock, src_addr, msg)

            dst_addr = MCTPSockAddr.for_ep_resp(self, src_addr, sock.addr_ext)
            rsp_flags = flags & 0x1f
            await sock.send(dst_addr, bytes([rsp_flags, opcode, 0x05]))

    iface = mctpd.system.interfaces[0]
    dev = NoUuidEndpoint(iface, bytes([0x1d]))
    mctpd.network.endpoints[0] = dev
    mctp = await mctpd_mctp_iface_obj(dbus, iface)
    static_eid = 210
    start_eid = 0

    (eid, _, path, new) = await mctp.call_assign_endpoint_static(
        dev.lladdr,
        static_eid,
        start_eid,
        b'',
        b''
    )

    assert eid == static_eid
    assert dev.eid == static_eid
    assert new

    ep = await dbus.get_proxy_object(MCTPD_C, path)
    ep_props = await ep.get_interface(DBUS_PROPERTIES_I)

    recovered = trio.Semaphore(initial_value=0)

    def ep_connectivity_changed(iface, changed, invalidated):
        if iface == MCTPD_ENDPOINT_I and 'Connectivity' in changed:
            if 'Available' == changed['Connectivity'].value:
                recovered.release()

    await ep_props.on_properties_changed(ep_connectivity_changed)

    dev.reset()

    ep_ep = await ep.get_interface(MCTPD_ENDPOINT_I)
    await ep_ep.call_recover()

    with trio.move_on_after(2 * MCTPD_TRECLAIM) as expected:
        await recovered.acquire()

    assert not expected.cancelled_caught
    assert dev.eid == static_eid
    assert mctpd.system.lookup_neighbour(iface, static_eid) is not None
    assert mctpd.system.lookup_route(iface.net, static_eid) is not None


async def test_assign_endpoint_static_allocated(dbus, mctpd):
    """Test that we can repeat an AssignEndpointStatic call with the same
    static EID
    """
    iface = mctpd.system.interfaces[0]
    mctp = await mctpd_mctp_iface_obj(dbus, iface)
    dev = mctpd.network.endpoints[0]
    static_eid = 12
    start_eid = 13
    ignore_eids = b''  # Empty array - no EIDs to ignore
    ignore_message_types = b''  # Empty array - no Message types to ignore

    (eid, _, _, new) = await mctp.call_assign_endpoint_static(
        dev.lladdr,
        static_eid,
        start_eid,
        ignore_eids,
        ignore_message_types
    )

    assert eid == static_eid
    assert new

    # repeat, same EID
    (eid, _, _, new) = await mctp.call_assign_endpoint_static(
        dev.lladdr,
        static_eid,
        start_eid,
        ignore_eids,
        ignore_message_types
    )

    assert eid == static_eid
    assert not new


async def test_assign_endpoint_static_conflict(dbus, mctpd):
    """Test that we cannot assign a conflicting static EID"""
    iface = mctpd.system.interfaces[0]
    mctp = await mctpd_mctp_iface_obj(dbus, iface)
    dev1 = mctpd.network.endpoints[0]

    dev2 = Endpoint(iface, bytes([0x1E]))
    mctpd.network.add_endpoint(dev2)

    # dynamic EID assigment for dev1
    (eid, _, _, new) = await mctp.call_assign_endpoint(
        dev1.lladdr,
    )

    assert new

    # try to assign dev2 with the dev1's existing EID
    ignore_eids = b''  # Empty array - no EIDs to ignore
    ignore_message_types = b''  # Empty array - no Message types to ignore
    with pytest.raises(asyncdbus.errors.DBusError) as ex:
        await mctp.call_assign_endpoint_static(dev2.lladdr, eid, 14, ignore_eids, ignore_message_types)

    assert str(ex.value) == "Address in use"


async def test_assign_endpoint_static_varies(dbus, mctpd):
    """Test that we cannot re-assign a static EID to an endpoint that already
    has a different EID allocated
    """
    iface = mctpd.system.interfaces[0]
    dev = mctpd.network.endpoints[0]
    mctp = await mctpd_mctp_iface_obj(dbus, iface)
    static_eid = 12
    start_eid = 13
    ignore_eids = b''  # Empty array - no EIDs to ignore
    ignore_message_types = b''  # Empty array - no Message types to ignore

    (eid, _, _, new) = await mctp.call_assign_endpoint_static(
        dev.lladdr,
        static_eid,
        start_eid,
        ignore_eids,
        ignore_message_types
    )

    assert eid == static_eid
    assert new

    with pytest.raises(asyncdbus.errors.DBusError) as ex:
        await mctp.call_assign_endpoint_static(dev.lladdr, 13, 14, ignore_eids, ignore_message_types)

    assert str(ex.value) == "Already assigned a different EID"


async def test_get_endpoint_id(dbus, mctpd, routed_ep):
    """Test that the mctpd control protocol responder support has support for a
    basic Get Endpoint ID command
    """
    ep = routed_ep

    cmd = MCTPControlCommand(True, 0, 0x02)
    rsp = await ep.send_control(mctpd.network.mctp_socket, cmd)

    # command code
    assert rsp[1] == 0x02
    # completion code indicates success
    assert rsp[2] == 0x00
    # EID matches the system
    assert rsp[3] == mctpd.system.addresses[0].eid


async def test_response_iid(mctpd):
    """Test that instance ID is populated correctly on control protocol
    responses
    """
    peer = mctpd.network.endpoints[0]
    for iid in [0, 1, 30, 31]:
        cmd = MCTPControlCommand(True, iid, 0x02)
        rsp = await peer.send_control(mctpd.network.mctp_socket, cmd)
        assert rsp[0] == iid


async def test_learn_endpoint_invalid_response_command(dbus, mctpd):
    """During a LearnEndpoint's Get Endpoint ID exchange, return a response
    from a different command; in this case Get Message Type Support, which
    happens to be the same length as a the expected Get Endpoint ID response.
    """

    class BusyEndpoint(Endpoint):
        async def handle_mctp_control(self, sock, src_addr, msg):
            flags, opcode = msg[0:2]
            if opcode != 2:
                return await super().handle_mctp_control(sock, src_addr, msg)
            dst_addr = MCTPSockAddr.for_ep_resp(self, src_addr, sock.addr_ext)
            msg = bytes([flags & 0x1F, 0x05, 0x00, 0x02, 0x00, 0x01])
            await sock.send(dst_addr, msg)

    iface = mctpd.system.interfaces[0]
    ep = BusyEndpoint(iface, bytes([0x1E]), eid=15)
    mctpd.network.add_endpoint(ep)
    mctp = await mctpd_mctp_iface_obj(dbus, iface)

    with pytest.raises(asyncdbus.errors.DBusError) as ex:
        await mctp.call_learn_endpoint(ep.lladdr)

    assert str(ex.value) == "Request failed"


async def test_setup_endpoint_invalid_set_eid_response(dbus, mctpd):
    """During a SetupEndpoint's Set Endpoint ID exchange, return a response
    that indicates that the EID has been set, but report an invalid (0) EID in
    the response.
    """

    class InvalidEndpoint(Endpoint):
        async def handle_mctp_control(self, sock, src_addr, msg):
            flags, opcode = msg[0:2]
            if opcode != 1:
                return await super().handle_mctp_control(sock, src_addr, msg)
            dst_addr = MCTPSockAddr.for_ep_resp(self, src_addr, sock.addr_ext)
            self.eid = msg[3]
            msg = bytes(
                [
                    flags & 0x1F,  # Rsp
                    0x01,  # opcode: Set Endpoint ID
                    0x00,  # cc: success
                    0x00,  # assignment accepted, no pool
                    0x00,  # set EID: invalid
                    0x00,  # pool size: 0
                ]
            )
            await sock.send(dst_addr, msg)

    iface = mctpd.system.interfaces[0]
    ep = InvalidEndpoint(iface, bytes([0x1E]), eid=0)
    mctpd.network.add_endpoint(ep)
    mctp = await mctpd_mctp_iface_obj(dbus, iface)

    with pytest.raises(asyncdbus.errors.DBusError) as ex:
        await mctp.call_setup_endpoint(ep.lladdr)

    assert str(ex.value) == "Endpoint returned failure to Set Endpoint ID"


async def test_setup_endpoint_vary_set_eid_response(dbus, mctpd):
    """During a SetupEndpoint's Set Endpoint ID exchange, return a response
    that indicates that the EID has been set, but report a different set EID in
    the response.
    """

    class VaryEndpoint(Endpoint):
        async def handle_mctp_control(self, sock, src_addr, msg):
            flags, opcode = msg[0:2]
            if opcode != 1:
                return await super().handle_mctp_control(sock, src_addr, msg)
            dst_addr = MCTPSockAddr.for_ep_resp(self, src_addr, sock.addr_ext)
            self.eid = msg[3] + 1
            msg = bytes(
                [
                    flags & 0x1F,  # Rsp
                    0x01,  # opcode: Set Endpoint ID
                    0x00,  # cc: success
                    0x00,  # assignment accepted, no pool
                    self.eid,  # set EID: valid, but not what was assigned
                    0x00,  # pool size: 0
                ]
            )
            await sock.send(dst_addr, msg)

    iface = mctpd.system.interfaces[0]
    ep = VaryEndpoint(iface, bytes([0x1E]))
    mctpd.network.add_endpoint(ep)
    mctp = await mctpd_mctp_iface_obj(dbus, iface)

    (eid, _, _, _) = await mctp.call_setup_endpoint(ep.lladdr)

    assert eid == ep.eid


async def test_setup_endpoint_conflicting_set_eid_response(dbus, mctpd):
    """During a SetupEndpoint's Set Endpoint ID exchange, return a response
    that indicates that the EID has been set, but report a different set EID in
    the response, which conflicts with another endpoint
    """

    class ConflictingEndpoint(Endpoint):
        def __init__(self, iface, lladdr, conflict_eid):
            super().__init__(iface, lladdr)
            self.conflict_eid = conflict_eid

        async def handle_mctp_control(self, sock, src_addr, msg):
            flags, opcode = msg[0:2]
            if opcode != 1:
                return await super().handle_mctp_control(sock, src_addr, msg)
            dst_addr = MCTPSockAddr.for_ep_resp(self, src_addr, sock.addr_ext)
            # reject reality, use a conflicting eid
            self.eid = self.conflict_eid
            msg = bytes(
                [
                    flags & 0x1F,  # Rsp
                    0x01,  # opcode: Set Endpoint ID
                    0x00,  # cc: success
                    0x00,  # assignment accepted, no pool
                    self.eid,  # set EID: valid, but not what was assigned
                    0x00,  # pool size: 0
                ]
            )
            await sock.send(dst_addr, msg)

    iface = mctpd.system.interfaces[0]
    ep1 = mctpd.network.endpoints[0]
    mctp = await mctpd_mctp_iface_obj(dbus, iface)
    (eid1, _, _, _) = await mctp.call_setup_endpoint(ep1.lladdr)
    assert eid1 == ep1.eid

    ep2 = ConflictingEndpoint(iface, bytes([0x1F]), ep1.eid)
    mctpd.network.add_endpoint(ep2)
    with pytest.raises(asyncdbus.errors.DBusError) as ex:
        await mctp.call_setup_endpoint(ep2.lladdr)

    assert "already used" in str(ex.value)


async def test_learn_endpoint_invalid_response_iid(dbus, mctpd):
    """Ensure a response with an invalid IID is discarded"""

    class InvalidIIDEndpoint(Endpoint):
        async def handle_mctp_control(self, sock, src_addr, msg):
            # bump IID
            flags = msg[0]
            iid_mask = 0x1D
            flags = (flags & ~iid_mask) | ((flags + 1) & iid_mask)
            msg = bytes([flags]) + msg[1:]
            return await super().handle_mctp_control(sock, src_addr, msg)

    iface = mctpd.system.interfaces[0]
    ep = InvalidIIDEndpoint(iface, bytes([0x1E]), eid=15)
    mctpd.network.add_endpoint(ep)
    mctp = await mctpd_mctp_iface_obj(dbus, iface)

    with pytest.raises(asyncdbus.errors.DBusError) as ex:
        await mctp.call_learn_endpoint(ep.lladdr)

    assert str(ex.value) == "Request failed"


async def test_query_message_types(dbus, mctpd):
    """Ensure we're parsing Get Message Type Support responses"""
    iface = mctpd.system.interfaces[0]
    ep = mctpd.network.endpoints[0]
    ep_types = [0, 1, 5]
    ep.types = ep_types

    mctp = await mctpd_mctp_iface_obj(dbus, iface)

    (eid, net, path, new) = await mctp.call_setup_endpoint(ep.lladdr)

    assert eid == ep.eid

    ep = await mctpd_mctp_endpoint_common_obj(dbus, path)

    query_types = list(await ep.get_supported_message_types())
    ep_types.sort()
    query_types.sort()

    assert ep_types == query_types


async def test_network_local_eids_single(dbus, mctpd):
    """Network1.LocalEIDs should reflect locally-assigned EID state"""
    iface = mctpd.system.interfaces[0]

    net = await mctpd_mctp_network_obj(dbus, iface.net)
    eids = list(await net.get_local_eids())

    assert eids == [8]


async def test_network_local_eids_multiple(dbus, mctpd):
    iface = mctpd.system.interfaces[0]
    await mctpd.system.add_address(mctpd.system.Address(iface, 9))

    net = await mctpd_mctp_network_obj(dbus, iface.net)
    eids = list(await net.get_local_eids())

    assert eids == [8, 9]


async def test_network_local_eids_none(dbus, mctpd):
    iface = mctpd.system.interfaces[0]
    await mctpd.system.del_address(mctpd.system.Address(iface, 8))

    net = await mctpd_mctp_network_obj(dbus, iface.net)
    eids = list(await net.get_local_eids())

    assert eids == []


async def test_concurrent_recovery_setup(dbus, mctpd, autojump_clock):
    iface = mctpd.system.interfaces[0]
    mctp_i = await mctpd_mctp_iface_obj(dbus, iface)

    # mctpd context tracks 20 peer objects by default, add and set up 19 so we
    # reach the allocation boundary.
    split = 19
    for i in range(split):
        pep = Endpoint(iface, bytes([0x1E + i]))
        mctpd.network.add_endpoint(pep)
        (_, _, path, _) = await mctp_i.call_setup_endpoint(pep.lladdr)

    # Grab the DBus path for an endpoint that we will cause to be removed from
    # the network through the recovery path. Arbitrarily use the most recent
    # one added
    ep = await dbus.get_proxy_object(MCTPD_C, path)
    ep_props = await ep.get_interface(DBUS_PROPERTIES_I)

    # Set up a match for Connectivity transitioning to Degraded on the endpoint
    # for which we request recovery
    degraded = trio.Semaphore(initial_value=0)

    def ep_connectivity_changed(iface, changed, invalidated):
        if iface == MCTPD_ENDPOINT_I and 'Connectivity' in changed:
            if 'Degraded' == changed['Connectivity'].value:
                degraded.release()

    await ep_props.on_properties_changed(ep_connectivity_changed)

    # Set up a match for the recovery endpoint object being removed from DBus
    mctp_p = await dbus.get_proxy_object(MCTPD_C, MCTPD_MCTP_P)
    mctp_objmgr = await mctp_p.get_interface(DBUS_OBJECT_MANAGER_I)
    removed = trio.Semaphore(initial_value=0)

    def ep_removed(ep_path, interfaces):
        if ep_path == path and MCTPD_ENDPOINT_I in interfaces:
            removed.release()

    await mctp_objmgr.on_interfaces_removed(ep_removed)

    # Delete the endpoint from the network so its recovery will fail after
    # timeout. Note we delete at the split index as the network was already
    # populated with the default endpoint
    del mctpd.network.endpoints[split]

    # Begin recovery for the endpoint ...
    ep_ep = await ep.get_interface(MCTPD_ENDPOINT_I)
    await ep_ep.call_recover()

    # ... and wait until we're notified the recovery process has begun
    with trio.move_on_after(1) as expected:
        await degraded.acquire()
    assert not expected.cancelled_caught

    # Now that we're asynchronously waiting for the endpoint recovery process
    # to complete, force a realloc() of the peer object array by adding a new
    # peer, which will invalidate the recovering peer's pointer
    pep = Endpoint(iface, bytes([0x1E + split]))
    mctpd.network.add_endpoint(pep)
    (_, _, _, new) = await mctp_i.call_setup_endpoint(pep.lladdr)
    assert new

    # Verify the recovery process completed gracefully with removal of the
    # endpoint's DBus object
    with trio.move_on_after(2 * MCTPD_TRECLAIM) as expected:
        await removed.acquire()
    assert not expected.cancelled_caught


async def test_bridged_learn_endpoint(dbus, mctpd):
    """Bridged EP can be discovered via Network1.LearnEndpoint"""
    iface = mctpd.system.interfaces[0]
    ep = mctpd.network.endpoints[0]
    br_ep = Endpoint(iface, bytes(), eid=10, types=[0, 2])
    ep.add_bridged_ep(br_ep)
    mctpd.network.add_endpoint(br_ep)

    await mctpd.system.add_route(mctpd.system.Route(br_ep.eid, 1, iface=iface))
    # static neighbour; no gateway route support at present
    await mctpd.system.add_neighbour(
        mctpd.system.Neighbour(iface, ep.lladdr, br_ep.eid)
    )

    net = await mctpd_mctp_network_obj(dbus, iface.net)
    (path, new) = await net.call_learn_endpoint(br_ep.eid)

    assert (
        path == f'/au/com/codeconstruct/mctp1/networks/1/endpoints/{br_ep.eid}'
    )
    assert new


async def test_network_learn_endpoint_absent(dbus, mctpd):
    iface = mctpd.system.interfaces[0]

    net = await mctpd_mctp_network_obj(dbus, iface.net)

    with pytest.raises(asyncdbus.errors.DBusError):
        await net.call_learn_endpoint(10)


async def test_change_network(dbus, mctpd):
    """Change a network id, while we have an active endpoint on that net"""
    iface = mctpd.system.interfaces[0]
    ep = mctpd.network.endpoints[0]

    net = await mctpd_mctp_network_obj(dbus, 1)
    assert net is not None

    iface.net = 2
    await mctpd.system.notify_interface(iface)

    # we should now have a new net at 2
    net = await mctpd_mctp_network_obj(dbus, 2)
    assert net is not None

    # and nothing at 1
    with pytest.raises(asyncdbus.errors.DBusError) as ex:
        await mctpd_mctp_network_obj(dbus, 1)
    assert (
        str(ex.value)
        == "Unknown object '/au/com/codeconstruct/mctp1/networks/1'."
    )

    # endpoint should be present under 2/
    ep = await mctpd_mctp_endpoint_common_obj(
        dbus, '/au/com/codeconstruct/mctp1/networks/2/endpoints/8'
    )
    assert ep is not None


async def test_del_interface_last(dbus, mctpd):
    """Delete our only interface"""
    iface = mctpd.system.interfaces[0]
    await mctpd.system.del_interface(iface)

    # interface should be gone
    with pytest.raises(asyncdbus.errors.DBusError):
        await mctpd_mctp_iface_obj(dbus, iface)

    # network should be gone
    with pytest.raises(asyncdbus.errors.DBusError):
        await mctpd_mctp_network_obj(dbus, iface.net)


async def test_del_interface_with_peers(dbus, mctpd):
    """Delete an interface with peers attached, ensure all are gone"""
    net = mctpd.system.interfaces[0].net
    iface = mctpd.system.Interface(
        'mctp1',
        2,
        net,
        bytes([0x10]),
        68,
        254,
        True,
    )
    await mctpd.system.add_interface(iface)

    eps = [
        Endpoint(iface, bytes([0x11])),
        Endpoint(iface, bytes([0x12])),
        Endpoint(iface, bytes([0x13])),
    ]

    mctp = await mctpd_mctp_iface_obj(dbus, iface)

    paths = []
    for ep in eps:
        mctpd.network.add_endpoint(ep)
        (eid, _, path, _) = await mctp.call_setup_endpoint(ep.lladdr)
        assert eid == ep.eid
        paths.append(path)

    await mctpd.system.del_interface(iface)

    # interface should be gone
    with pytest.raises(asyncdbus.errors.DBusError):
        await mctpd_mctp_iface_obj(dbus, iface)

    # .. but the network should remain, as the default interface is still
    # present
    _ = await mctpd_mctp_network_obj(dbus, net)

    for path in paths:
        with pytest.raises(asyncdbus.errors.DBusError) as ex:
            ep = await mctpd_mctp_endpoint_common_obj(dbus, path)
        assert str(ex.value).startswith("Unknown object")


async def test_add_interface(dbus, mctpd):
    """Remove and re-add an interface"""
    net = 1
    #dummy eid to start with
    start_eid = 10
    ignore_eids = b''  # Empty array - no EIDs to ignore
    ignore_message_types = b''  # Empty array - no Message types to ignore
    # Create a new netdevice
    iface = mctpd.system.Interface('mctpnew', 10, net, bytes([]), 68, 254, True)
    await mctpd.system.add_interface(iface)
    await mctpd.system.add_address(mctpd.system.Address(iface, 88))
    mctp = await mctpd_mctp_iface_obj(dbus, iface)

    # Add an endpoint on the interface
    mctpd.network.add_endpoint(Endpoint(iface, bytes([]), types=[0, 1]))

    static_eid = 30
    (eid, _, _, new) = await mctp.call_assign_endpoint_static(
        bytes([]),
        static_eid,
        start_eid,
        ignore_eids,
        ignore_message_types
    )
    assert eid == static_eid
    assert new
    assert mctpd.system.lookup_route(net, static_eid).iface == iface

    # Remove the netdevice
    await mctpd.system.del_interface(iface)

    # Interface should be gone
    with pytest.raises(asyncdbus.errors.DBusError):
        await mctpd_mctp_iface_obj(dbus, iface)
    assert mctpd.system.lookup_route(net, static_eid) is None

    # Re-add the same interface name again, with a new ifindex 11
    iface = mctpd.system.Interface('mctpnew', 11, net, bytes([]), 68, 254, True)
    await mctpd.system.add_interface(iface)
    await mctpd.system.add_address(mctpd.system.Address(iface, 89))
    mctp = await mctpd_mctp_iface_obj(dbus, iface)

    # Add an endpoint on the interface
    mctpd.network.add_endpoint(Endpoint(iface, bytes([]), types=[0, 1]))

    # Old route should still be gone
    assert mctpd.system.lookup_route(net, static_eid) is None

    static_eid = 40
    (eid, _, _, new) = await mctp.call_assign_endpoint_static(
        bytes([]),
        static_eid,
        start_eid,
        ignore_eids,
        ignore_message_types
    )
    assert eid == static_eid
    assert new
    assert mctpd.system.lookup_route(net, static_eid).iface == iface


async def test_interface_rename(dbus, mctpd):
    iface = mctpd.system.interfaces[0]
    iface_obj = await mctpd_mctp_iface_obj(dbus, iface)
    assert iface_obj.path.endswith(iface.name)

    new_name = "newmctp0"
    iface.name = new_name
    await mctpd.system.notify_interface(iface)

    iface_obj = await mctpd_mctp_iface_obj(dbus, iface)
    assert iface_obj.path.endswith(new_name)


async def test_interface_rename_with_peers(dbus, mctpd):
    iface = mctpd.system.interfaces[0]
    ep = mctpd.network.endpoints[0]

    iface_obj = await mctpd_mctp_iface_obj(dbus, iface)
    assert iface_obj.path.endswith(iface.name)

    # access the endpoint object before rename
    (_, _, ep_path, _) = await iface_obj.call_setup_endpoint(ep.lladdr)
    ep_obj = await dbus.get_proxy_object(MCTPD_C, ep_path)

    new_name = "newmctp0"
    iface.name = new_name
    await mctpd.system.notify_interface(iface)

    iface_obj = await mctpd_mctp_iface_obj(dbus, iface)
    assert iface_obj.path.endswith(new_name)

    # ensure the endpoint persists after rename
    ep_obj = await dbus.get_proxy_object(MCTPD_C, ep_path)
    assert ep_obj is not None

""" Test that we allocate Eids to MCTP Bridge Endpoints"""
async def test_endpoint_allocate_eid(dbus, mctpd):
    iface = mctpd.system.interfaces[0]
    bridge = mctpd.network.endpoints[0]
    ep_types = [0, 1, 5]
    bridge.types = ep_types
    static_eid = 12
    start_eid = 13
    pool_size = 2
    ignore_eids = b''  # Empty array - no EIDs to ignore
    ignore_message_types = b''  # Empty array - no Message types to ignore

    # mimicing MCTP Bridge by adding Bridg's Endpoints to same network and physcial address
    for eid in range(start_eid, start_eid + pool_size):
        br_ep = Endpoint(iface, bytes(), types = [0,1,2,eid], eid= eid)	
        bridge.add_bridged_ep(br_ep)
        mctpd.network.add_endpoint(br_ep)
        await mctpd.system.add_route(mctpd.system.Route(br_ep.eid, 1, iface = iface))
        await mctpd.system.add_neighbour(mctpd.system.Neighbour(iface, bridge.lladdr, br_ep.eid))

    # first assign enpoint to MCTP Bridge and later involk allocate endpoint ids
    # this will add Brige's enpoints routes and neigh and update dbus
    mctp = await mctpd_mctp_iface_obj(dbus, bridge.iface)
    (eid, _, path, _) = await mctp.call_assign_endpoint_static(
        bridge.lladdr,
        static_eid,
        start_eid,
        ignore_eids,
        ignore_message_types
    )

    # non blocking sleep for Allocate Eid timer expiry
    await trio.sleep(5)
    assert eid == static_eid

    #  check if networks neighbours are reflecting the mctpd added bridge's neighbours
    assert len(mctpd.system.neighbours) == (1 + pool_size)

    neigh = mctpd.system.neighbours[0]
    assert neigh.lladdr == bridge.lladdr
    assert neigh.eid == start_eid

    neigh = mctpd.system.neighbours[1]
    assert neigh.lladdr == bridge.lladdr
    assert neigh.eid == start_eid + 1

    # check one of Bridge's endpoint types per dbus property
    path = path.rsplit('/endpoints', 1)[0]
    path = path + f"/endpoints/{mctpd.network.endpoints[1].eid}"
    ep = await mctpd_mctp_endpoint_common_obj(dbus, path)
    query_types = list(await ep.get_supported_message_types())
    assert (query_types == mctpd.network.endpoints[1].types)

""" Test that ignore_eids parameter works correctly """
async def test_assign_endpoint_static_with_ignore_eids(dbus, mctpd):
    iface = mctpd.system.interfaces[0]
    dev = mctpd.network.endpoints[0]
    mctp = await mctpd_mctp_iface_obj(dbus, iface)
    static_eid = 12
    start_eid = 13
    ignore_eids = bytes([20, 21, 22])  # EIDs to ignore
    ignore_message_types = b''  # Message types to ignore

    (eid, _, _, new) = await mctp.call_assign_endpoint_static(
        dev.lladdr,
        static_eid,
        start_eid,
        ignore_eids,
        ignore_message_types
    )

    assert eid == static_eid
    assert new

    assert len(mctpd.system.neighbours) == 1
    neigh = mctpd.system.neighbours[0]
    assert neigh.lladdr == dev.lladdr
    assert neigh.eid == static_eid
    assert len(mctpd.system.routes) == 2

""" Bridge pool: gateway routes are installed per-EID with extent 0 for every
pool EID *except* those in ignore_eids, and use the bridge's own EID as gw."""
async def test_pool_gw_routes_skip_ignore_eids(dbus, mctpd):
    iface = mctpd.system.interfaces[0]
    bridge = mctpd.network.endpoints[0]
    bridge.types = [0, 1, 5]

    bridge_eid = 12
    pool_start = 13
    pool_size = 5
    ignore_eids = bytes([14, 16])
    ignore_message_types = b''

    for _ in range(pool_size):
        bridge.add_bridged_ep(Endpoint(iface, bytes(), types=[0]))

    mctp = await mctpd_mctp_iface_obj(dbus, bridge.iface)
    (eid, _, _, _) = await mctp.call_assign_endpoint_static(
        bridge.lladdr,
        bridge_eid,
        pool_start,
        ignore_eids,
        ignore_message_types,
    )
    assert eid == bridge_eid

    pool_eids = set(range(pool_start, pool_start + pool_size))
    ignored = set(ignore_eids)
    expected_gw_eids = pool_eids - ignored

    gw_routes = {}
    for rt in mctpd.system.routes:
        if rt.gw is not None and rt.gw[1] == bridge_eid:
            assert rt.start_eid == rt.end_eid, (
                f"pool gw route {rt} must be per-EID (extent 0), "
                f"got range {rt.start_eid}-{rt.end_eid}"
            )
            gw_routes[rt.start_eid] = rt

    for e in expected_gw_eids:
        assert e in gw_routes, (
            f"missing gateway route for pool EID {e} via bridge {bridge_eid}; "
            f"installed gw routes: {sorted(gw_routes)}"
        )

    for e in ignored:
        assert e not in gw_routes, (
            f"unexpected gateway route for ignored EID {e}; "
            f"installed gw routes: {sorted(gw_routes)}"
        )

    assert set(gw_routes) == expected_gw_eids, (
        f"gw route set {sorted(gw_routes)} != expected {sorted(expected_gw_eids)}"
    )

async def _setup_bridge_with_pool(dbus, mctpd, bridge_eid, pool_start,
                                  pool_size, ignore_eids):
    iface = mctpd.system.interfaces[0]
    bridge = mctpd.network.endpoints[0]
    bridge.types = [0, 1, 5]

    for _ in range(pool_size):
        bridge.add_bridged_ep(Endpoint(iface, bytes(), types=[0]))

    mctp = await mctpd_mctp_iface_obj(dbus, bridge.iface)
    (eid, _, path, _) = await mctp.call_assign_endpoint_static(
        bridge.lladdr,
        bridge_eid,
        pool_start,
        ignore_eids,
        b'',
    )
    assert eid == bridge_eid
    return bridge, path

def _pool_gw_route_eids(routes, bridge_eid):
    found = {}
    for rt in routes:
        if rt.gw is not None and rt.gw[1] == bridge_eid:
            assert rt.start_eid == rt.end_eid, (
                f"pool gw route {rt} must be per-EID (extent 0), "
                f"got range {rt.start_eid}-{rt.end_eid}"
            )
            found[rt.start_eid] = rt
    return found

""" Empty ignore_eids: every pool EID must still get its own per-EID gw route
(extent 0). Regression guard against falling back to a single range route. """
async def test_pool_gw_routes_empty_ignore_list(dbus, mctpd):
    bridge_eid, pool_start, pool_size = 12, 13, 4
    _, _ = await _setup_bridge_with_pool(
        dbus, mctpd, bridge_eid, pool_start, pool_size, b''
    )

    gw_routes = _pool_gw_route_eids(mctpd.system.routes, bridge_eid)
    assert set(gw_routes) == set(range(pool_start, pool_start + pool_size))

""" Whole pool in ignore list: walker must iterate every EID through the
should_ignore_eid() continue branch and install zero gw routes, without
errors. """
async def test_pool_gw_routes_whole_pool_ignored(dbus, mctpd):
    bridge_eid, pool_start, pool_size = 12, 13, 3
    ignore_eids = bytes(range(pool_start, pool_start + pool_size))
    _, _ = await _setup_bridge_with_pool(
        dbus, mctpd, bridge_eid, pool_start, pool_size, ignore_eids
    )

    gw_routes = _pool_gw_route_eids(mctpd.system.routes, bridge_eid)
    assert gw_routes == {}, (
        f"expected no gw routes when whole pool is ignored, got {sorted(gw_routes)}"
    )

""" Ignore list disjoint from pool: should_ignore_eid() never matches, so
every pool EID gets a gw route. Catches a bug where the ignore lookup
matched by index rather than EID value. """
async def test_pool_gw_routes_disjoint_ignore_list(dbus, mctpd):
    bridge_eid, pool_start, pool_size = 12, 13, 4
    ignore_eids = bytes([200, 201, 202])
    _, _ = await _setup_bridge_with_pool(
        dbus, mctpd, bridge_eid, pool_start, pool_size, ignore_eids
    )

    gw_routes = _pool_gw_route_eids(mctpd.system.routes, bridge_eid)
    assert set(gw_routes) == set(range(pool_start, pool_start + pool_size))

""" Delete path: removing the bridge peer must drop every gw route that the
add path installed, exercising del_pool_gw_routes_ignore_aware (the
adding=false branch of walk_pool_gw_routes). Ignored EIDs were never
installed and must not be requested for deletion. """
async def test_pool_gw_routes_delete_path_honors_ignore(dbus, mctpd):
    bridge_eid, pool_start, pool_size = 12, 13, 5
    ignore_eids = bytes([14, 16])
    bridge, ep_path = await _setup_bridge_with_pool(
        dbus, mctpd, bridge_eid, pool_start, pool_size, ignore_eids
    )

    before = _pool_gw_route_eids(mctpd.system.routes, bridge_eid)
    expected_installed = set(range(pool_start, pool_start + pool_size)) - set(ignore_eids)
    assert set(before) == expected_installed, (
        f"precondition: gw routes after add = {sorted(before)}, "
        f"expected {sorted(expected_installed)}"
    )

    ep = await mctpd_mctp_endpoint_control_obj(dbus, ep_path)
    await ep.call_remove()

    after = _pool_gw_route_eids(mctpd.system.routes, bridge_eid)
    assert after == {}, (
        f"gw routes remaining after Remove: {sorted(after)} "
        f"(should be empty)"
    )

""" Test that we use the minimum EID from the dynamic_eid_range config """
async def test_config_dyn_eid_range_min(nursery, dbus, sysnet):
    """Test that we use the minimum EID from the dynamic_eid_range config"""
    (min_dyn_eid, max_dyn_eid) = (20, 254)
    config = f"""
    [bus-owner]
    dynamic_eid_range = [{min_dyn_eid}, {max_dyn_eid}]
    """

    # since we're specifying per-test config, we create the wrapper directly
    # rather than using the fixture.
    mctpd = MctpdWrapper(dbus, sysnet, config=config)
    await mctpd.start_mctpd(nursery)

    iface = mctpd.system.interfaces[0]
    ep = mctpd.network.endpoints[0]

    mctp = await mctpd_mctp_iface_obj(dbus, iface)
    (eid, net, path, new) = await mctp.call_setup_endpoint(ep.lladdr)
    assert eid == min_dyn_eid
    assert ep.eid == eid

    res = await mctpd.stop_mctpd()
    assert res == 0


async def test_config_dyn_eid_range_max(nursery, dbus, sysnet):
    """Test that we use the maximum EID from the dynamic_eid_range config"""
    (min_dyn_eid, max_dyn_eid) = (20, 21)
    config = f"""
    [bus-owner]
    dynamic_eid_range = [{min_dyn_eid}, {max_dyn_eid}]
    """

    mctpd = MctpdWrapper(dbus, sysnet, config=config)
    await mctpd.start_mctpd(nursery)

    iface = mctpd.system.interfaces[0]
    mctp = await mctpd_mctp_iface_obj(dbus, iface)

    mctpd.network.add_endpoint(Endpoint(iface, bytes([0x01]), types=[0, 1]))
    mctpd.network.add_endpoint(Endpoint(iface, bytes([0x02]), types=[0, 1]))

    for i in range(0, 2):
        ep = mctpd.network.endpoints[i]
        (eid, net, path, new) = await mctp.call_setup_endpoint(ep.lladdr)
        assert eid >= 20 and eid <= 21

    # we should have run out of EIDs
    with pytest.raises(asyncdbus.errors.DBusError) as ex:
        ep = mctpd.network.endpoints[2]
        (eid, net, path, new) = await mctp.call_setup_endpoint(ep.lladdr)

    assert str(ex.value) == "Ran out of EIDs"
    assert mctpd.network.endpoints[2].eid == 0

    res = await mctpd.stop_mctpd()
    assert res == 0

""" Test that the service readiness interface is present and has correct initial state """
async def test_service_readiness_interface_present(dbus, mctpd):
    iface = mctpd.system.interfaces[0]
    
    # Get the service readiness interface object
    service_readiness = await mctpd_service_readiness_obj(dbus, iface)
    
    # Verify ServiceType property is correct and constant
    service_type = await service_readiness.get_service_type()
    assert service_type == SERVICE_TYPE_MCTP
    
    # Verify initial State property is "Starting"
    state = await service_readiness.get_state()
    assert state == SERVICE_STATE_STARTING


""" Test that service readiness state changes from Starting to Enabled after endpoint discovery """
async def test_service_readiness_state_transition(dbus, mctpd):
    iface = mctpd.system.interfaces[0]
    ep = mctpd.network.endpoints[0]
    
    # Get the interface object for SetupEndpoint call
    iface_obj = await mctpd_mctp_iface_obj(dbus, iface)
    
    # Get the service readiness interface object
    service_readiness = await mctpd_service_readiness_obj(dbus, iface)
    
    # Verify initial state is Starting
    initial_state = await service_readiness.get_state()
    assert initial_state == SERVICE_STATE_STARTING
    
    # Set up signal monitoring for state change
    state_changed = trio.Semaphore(initial_value=0)
    def on_state_changed(iface, changed, invalidated):
        if iface == OPENBMC_SERVICE_READINESS_I and 'State' in changed:
            if changed['State'].value == SERVICE_STATE_ENABLED:
                state_changed.release()
    
    # Get the interface object to monitor properties
    iface_monitor_obj = await dbus.get_proxy_object(
        'au.com.codeconstruct.MCTP1',
        '/au/com/codeconstruct/mctp1/interfaces/' + iface.name
    )
    props = await iface_monitor_obj.get_interface(DBUS_PROPERTIES_I)
    await props.on_properties_changed(on_state_changed)
    
    # Call SetupEndpoint to trigger discovery completion
    (eid, net, path, new) = await iface_obj.call_setup_endpoint(ep.lladdr)
    
    # Wait for the state to change to Enabled
    with trio.move_on_after(5) as expected:
        await state_changed.acquire()
    
    assert not expected.cancelled_caught, "Service readiness state did not transition to Enabled"
    
    # Verify the state is now Enabled
    final_state = await service_readiness.get_state()
    assert final_state == SERVICE_STATE_ENABLED


""" Test that service readiness state changes for bridge endpoints after routing table processing """
async def test_service_readiness_bridge_state_transition(dbus, mctpd):
    iface = mctpd.system.interfaces[0]
    bridge = mctpd.network.endpoints[0]
    static_eid = 12
    start_eid = 13
    ignore_eids = b''  # Empty array - no EIDs to ignore
    ignore_message_types = b''  # Empty array - no Message types to ignore
    
    # Get the interface object for AssignEndpoint call
    iface_obj = await mctpd_mctp_iface_obj(dbus, iface)
    
    # Get the service readiness interface object
    service_readiness = await mctpd_service_readiness_obj(dbus, iface)
    
    # Verify initial state is Starting
    initial_state = await service_readiness.get_state()
    assert initial_state == SERVICE_STATE_STARTING
    
    # Set up signal monitoring for state change
    state_changed = trio.Semaphore(initial_value=0)
    def on_state_changed(iface, changed, invalidated):
        if iface == OPENBMC_SERVICE_READINESS_I and 'State' in changed:
            if changed['State'].value == SERVICE_STATE_ENABLED:
                state_changed.release()
    
    # Get the interface object to monitor properties
    iface_monitor_obj = await dbus.get_proxy_object(
        'au.com.codeconstruct.MCTP1',
        '/au/com/codeconstruct/mctp1/interfaces/' + iface.name
    )
    props = await iface_monitor_obj.get_interface(DBUS_PROPERTIES_I)
    await props.on_properties_changed(on_state_changed)
    
    (eid, _, _, _) = await iface_obj.call_assign_endpoint_static(
        bridge.lladdr,
        static_eid,
        start_eid,
        ignore_eids,
        ignore_message_types
    )

    # non blocking sleep for Allocate Eid timer expiry
    await trio.sleep(5)
    assert eid == static_eid
    
    # Wait for the state to change to Enabled (may take longer for bridges)
    with trio.move_on_after(10) as expected:
        await state_changed.acquire()
    
    assert not expected.cancelled_caught, "Bridge service readiness state did not transition to Enabled"
    
    # Verify the state is now Enabled
    # TODO: The test infra does not have full bridge and routing table support
    # yet. So this does not quite take the intended path. When we merge the
    # pool size support, we can actually add a bridged endpoint and test the
    # routing table flow.
    final_state = await service_readiness.get_state()
    assert final_state == SERVICE_STATE_ENABLED

""" Test that service readiness interface is available on all network interfaces """
async def test_service_readiness_all_interfaces(dbus, mctpd):
    # Test with the default interface
    iface = mctpd.system.interfaces[0]
    service_readiness = await mctpd_service_readiness_obj(dbus, iface)
    
    # Verify service readiness interface exists
    assert service_readiness is not None
    
    # Test with a newly added interface
    net = 2
    start_eid = 10
    new_iface = mctpd.system.Interface('mctptest', 20, net, bytes([]), 68, 254, True)
    await mctpd.system.add_interface(new_iface)
    await mctpd.system.add_address(mctpd.system.Address(new_iface, 90))
    
    new_service_readiness = await mctpd_service_readiness_obj(dbus, new_iface)
    
    # Verify service readiness interface exists on new interface too
    assert new_service_readiness is not None
    
    # Verify both interfaces start with Starting state
    state1 = await service_readiness.get_state()
    state2 = await new_service_readiness.get_state()
    assert state1 == SERVICE_STATE_STARTING
    assert state2 == SERVICE_STATE_STARTING
    
    # Clean up
    await mctpd.system.del_interface(new_iface)


""" Test that service readiness state persists across interface renames """
async def test_service_readiness_rename_persistence(dbus, mctpd):
    iface = mctpd.system.interfaces[0]
    
    # Get initial service readiness state
    service_readiness = await mctpd_service_readiness_obj(dbus, iface)
    initial_state = await service_readiness.get_state()
    assert initial_state == SERVICE_STATE_STARTING
    
    # Rename the interface
    new_name = "renamedmctp0"
    iface.name = new_name
    await mctpd.system.notify_interface(iface)
    
    # Get the renamed interface object
    renamed_service_readiness = await mctpd_service_readiness_obj(dbus, iface)
    
    # Verify the service readiness interface still exists and has the same state
    renamed_state = await renamed_service_readiness.get_state()
    assert renamed_state == SERVICE_STATE_STARTING
    
    # Verify ServiceType is still correct
    service_type = await renamed_service_readiness.get_service_type()
    assert service_type == SERVICE_TYPE_MCTP


""" Test comprehensive service readiness behavior including signal emission """
async def test_service_readiness_comprehensive(dbus, mctpd):
    iface = mctpd.system.interfaces[0]
    ep = mctpd.network.endpoints[0]
    
    # Get the service readiness interface object
    service_readiness = await mctpd_service_readiness_obj(dbus, iface)
    
    # Verify initial state
    initial_state = await service_readiness.get_state()
    assert initial_state == SERVICE_STATE_STARTING
    
    # Verify ServiceType is constant
    service_type = await service_readiness.get_service_type()
    assert service_type == SERVICE_TYPE_MCTP
    
    # Set up signal monitoring for state changes
    state_changes = []
    def on_state_changed(iface, changed, invalidated):
        if iface == OPENBMC_SERVICE_READINESS_I and 'State' in changed:
            state_changes.append(changed['State'].value)
    
    # Get the interface object to monitor properties
    iface_monitor_obj = await dbus.get_proxy_object(
        'au.com.codeconstruct.MCTP1',
        '/au/com/codeconstruct/mctp1/interfaces/' + iface.name
    )
    props = await iface_monitor_obj.get_interface(DBUS_PROPERTIES_I)
    await props.on_properties_changed(on_state_changed)
    
    # Get the interface object for SetupEndpoint call
    iface_obj = await mctpd_mctp_iface_obj(dbus, iface)
    
    # Call SetupEndpoint to trigger discovery completion
    (eid, net, path, new) = await iface_obj.call_setup_endpoint(ep.lladdr)
    
    # Wait a bit for the signal to be processed
    await trio.sleep(0.5)
    
    # Verify that the state change signal was emitted
    assert len(state_changes) > 0, "No state change signals were emitted"
    assert SERVICE_STATE_ENABLED in state_changes, f"Expected state change to {SERVICE_STATE_ENABLED}, got {state_changes}"
    
    # Verify the final state is Enabled
    final_state = await service_readiness.get_state()
    assert final_state == SERVICE_STATE_ENABLED
    
    # Verify that the state only changed once (from Starting to Enabled)
    assert len(state_changes) == 1, f"Expected exactly one state change, got {len(state_changes)}: {state_changes}"
    assert state_changes[0] == SERVICE_STATE_ENABLED

""" Test EndpointPing D-Bus method """
async def test_endpoint_ping(dbus, mctpd):
    iface = mctpd.system.interfaces[0]
    ep = mctpd.network.endpoints[0]
    mctp = await mctpd_mctp_iface_obj(dbus, iface)

    # Set up the endpoint first
    (eid, _, _, _) = await mctp.call_setup_endpoint(ep.lladdr)

    # Get Network interface
    net = await mctpd_mctp_network_obj(dbus, iface.net)

    # Test EndpointPing
    # It should succeed and return nothing
    assert await net.call_endpoint_ping(eid) is None

""" Test EndpointPing with non-existent EID """
async def test_endpoint_ping_nonexistent(dbus, mctpd):
    iface = mctpd.system.interfaces[0]

    # Get Network interface
    net = await mctpd_mctp_network_obj(dbus, iface.net)

    # Try with an EID that hasn't been assigned/discovered
    nonexistent_eid = 200

    with pytest.raises(asyncdbus.errors.DBusError) as ex:
        await net.call_endpoint_ping(nonexistent_eid)

    # Should fail with "MCTP Endpoint did not respond"
    assert "MCTP Endpoint did not respond" in str(ex.value)

""" Test that the already discovered endpoint emits a property
change signal when the endpoint is learned """
async def test_learn_endpoint_emit_prop_signal(dbus, mctpd):
    iface = mctpd.system.interfaces[0]
    ep = mctpd.network.endpoints[0]
    mctp = await mctpd_mctp_iface_obj(dbus, iface)

    # Set up endpoint first
    (eid, net, path, new) = await mctp.call_setup_endpoint(ep.lladdr)

    ep_obj = await dbus.get_proxy_object(MCTPD_C, path)
    ep_props = await ep_obj.get_interface(DBUS_PROPERTIES_I)

    # Wait for connectivity change signal for discovered endpoint
    learned = trio.Semaphore(initial_value = 0)
    def ep_connectivity_changed(iface, changed, invalidated):
        if iface == MCTPD_ENDPOINT_I and \
                'Connectivity' in changed:
            if 'Available' == changed['Connectivity'].value:
                learned.release()

    await ep_props.on_properties_changed(ep_connectivity_changed)

    # Learn the endpoint
    (_, _, learned_path, _) = await mctp.call_learn_endpoint(ep.lladdr)
    assert learned_path == path
    # Wait for the property change signal with timeout
    with trio.fail_after(5) as timeout:
        await learned.acquire()

    assert not timeout.cancelled_caught

""" Test EndpointPing with a device that returns a mismatched IID.
This verifies that we ignore validation errors and treat any response as success.
"""
async def test_endpoint_ping_bad_iid(dbus, mctpd):
    class BadIIDEndpoint(Endpoint):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.inject_error = False

        async def handle_mctp_control(self, sock, src_addr, msg):
            # Standard response handling, but we corrupt the IID in the response
            flags, opcode = msg[0:2]
            
            # Only intercept Get Endpoint UUID (opcode 0x03) which Ping uses
            if self.inject_error and opcode == 0x03:
                dst_addr = MCTPSockAddr.for_ep_resp(self, src_addr, sock.addr_ext)
                
                # Construct a valid-looking response but with WRONG IID
                # Request IID is in msg[0] & 0x1f. We'll use (IID + 1) % 32
                req_iid = flags & 0x1f
                bad_iid = (req_iid + 1) % 32
                
                resp_flags = (flags & ~0x1f) | bad_iid # Keep other flags, set bad IID
                
                # Response format: Header(2) + CC(1) + UUID(16)
                # We can just send a dummy UUID
                dummy_uuid = bytes([0xAA] * 16)
                
                resp = bytes([resp_flags, opcode, 0x00]) + dummy_uuid
                await sock.send(dst_addr, resp)
                return

            return await super().handle_mctp_control(sock, src_addr, msg)

    iface = mctpd.system.interfaces[0]
    
    # Create our bad endpoint
    ep = BadIIDEndpoint(iface, bytes([0x1e]))
    mctpd.network.add_endpoint(ep)
    
    mctp = await mctpd_mctp_iface_obj(dbus, iface)

    # Set up the endpoint first (standard setup)
    (eid, _, _, _) = await mctp.call_setup_endpoint(ep.lladdr)

    # Enable error injection for Ping
    ep.inject_error = True

    # Get Network interface
    net = await mctpd_mctp_network_obj(dbus, iface.net)

    # Test EndpointPing
    # It SHOULD succeed despite the bad IID in the response
    assert await net.call_endpoint_ping(eid) is None

""" Test EndpointPing with a device that returns wrong opcode.
This verifies that we ignore validation errors and treat any response as success.
"""
async def test_endpoint_ping_wrong_opcode(dbus, mctpd):
    class WrongOpcodeEndpoint(Endpoint):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.inject_error = False

        async def handle_mctp_control(self, sock, src_addr, msg):
            flags, opcode = msg[0:2]
            
            # Only intercept Get Endpoint UUID (opcode 0x03)
            if self.inject_error and opcode == 0x03:
                dst_addr = MCTPSockAddr.for_ep_resp(self, src_addr, sock.addr_ext)
                
                # Send back a response with WRONG opcode (e.g., 0x05 instead of 0x03)
                wrong_opcode = 0x05
                dummy_uuid = bytes([0xBB] * 16)
                
                resp = bytes([flags, wrong_opcode, 0x00]) + dummy_uuid
                await sock.send(dst_addr, resp)
                return

            return await super().handle_mctp_control(sock, src_addr, msg)

    iface = mctpd.system.interfaces[0]
    ep = WrongOpcodeEndpoint(iface, bytes([0x1f]))
    mctpd.network.add_endpoint(ep)
    
    mctp = await mctpd_mctp_iface_obj(dbus, iface)
    (eid, _, _, _) = await mctp.call_setup_endpoint(ep.lladdr)

    # Enable error injection for Ping
    ep.inject_error = True

    net = await mctpd_mctp_network_obj(dbus, iface.net)
    
    # Should succeed despite wrong opcode
    assert await net.call_endpoint_ping(eid) is None

""" Test EndpointPing with a device that returns an error completion code.
This verifies that we treat error responses as successful pings.
"""
async def test_endpoint_ping_error_completion_code(dbus, mctpd):
    class ErrorCompletionEndpoint(Endpoint):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.inject_error = False

        async def handle_mctp_control(self, sock, src_addr, msg):
            flags, opcode = msg[0:2]
            
            # Only intercept Get Endpoint UUID (opcode 0x03)
            if self.inject_error and opcode == 0x03:
                dst_addr = MCTPSockAddr.for_ep_resp(self, src_addr, sock.addr_ext)
                
                # Send back error response with completion code 0x05 (unsupported command)
                # Format: flags, opcode, completion_code
                resp = bytes([flags, opcode, 0x05])
                await sock.send(dst_addr, resp)
                return

            return await super().handle_mctp_control(sock, src_addr, msg)

    iface = mctpd.system.interfaces[0]
    ep = ErrorCompletionEndpoint(iface, bytes([0x20]))
    mctpd.network.add_endpoint(ep)
    
    mctp = await mctpd_mctp_iface_obj(dbus, iface)
    (eid, _, _, _) = await mctp.call_setup_endpoint(ep.lladdr)

    # Enable error injection for Ping
    ep.inject_error = True

    net = await mctpd_mctp_network_obj(dbus, iface.net)
    
    # Should succeed despite error completion code
    assert await net.call_endpoint_ping(eid) is None

""" Test EndpointPing with a device that returns truncated/short response.
This verifies that we treat short responses as successful pings.
"""
async def test_endpoint_ping_short_response(dbus, mctpd):
    class ShortResponseEndpoint(Endpoint):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.inject_error = False

        async def handle_mctp_control(self, sock, src_addr, msg):
            flags, opcode = msg[0:2]
            
            # Only intercept Get Endpoint UUID (opcode 0x03)
            if self.inject_error and opcode == 0x03:
                dst_addr = MCTPSockAddr.for_ep_resp(self, src_addr, sock.addr_ext)
                
                # Send back a response that's too short (missing UUID data)
                # Normal response should be: flags + opcode + cc + 16-byte UUID = 19 bytes
                # We send only 5 bytes
                resp = bytes([flags, opcode, 0x00, 0xCC, 0xDD])
                await sock.send(dst_addr, resp)
                return

            return await super().handle_mctp_control(sock, src_addr, msg)

    iface = mctpd.system.interfaces[0]
    ep = ShortResponseEndpoint(iface, bytes([0x21]))
    mctpd.network.add_endpoint(ep)
    
    mctp = await mctpd_mctp_iface_obj(dbus, iface)
    (eid, _, _, _) = await mctp.call_setup_endpoint(ep.lladdr)

    # Enable error injection for Ping
    ep.inject_error = True

    net = await mctpd_mctp_network_obj(dbus, iface.net)
    
    # Should succeed despite short response
    assert await net.call_endpoint_ping(eid) is None

""" Test EndpointPing with a device that returns garbage data.
This verifies that we treat any response as successful ping.
"""
async def test_endpoint_ping_garbage_response(dbus, mctpd):
    class GarbageResponseEndpoint(Endpoint):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.inject_error = False

        async def handle_mctp_control(self, sock, src_addr, msg):
            flags, opcode = msg[0:2]
            
            # Only intercept Get Endpoint UUID (opcode 0x03)
            if self.inject_error and opcode == 0x03:
                dst_addr = MCTPSockAddr.for_ep_resp(self, src_addr, sock.addr_ext)
                
                # Send back completely garbage data
                resp = bytes([0xFF, 0xFF, 0xFF, 0xFF, 0xFF])
                await sock.send(dst_addr, resp)
                return

            return await super().handle_mctp_control(sock, src_addr, msg)

    iface = mctpd.system.interfaces[0]
    ep = GarbageResponseEndpoint(iface, bytes([0x22]))
    mctpd.network.add_endpoint(ep)
    
    mctp = await mctpd_mctp_iface_obj(dbus, iface)
    (eid, _, _, _) = await mctp.call_setup_endpoint(ep.lladdr)

    # Enable error injection for Ping
    ep.inject_error = True

    net = await mctpd_mctp_network_obj(dbus, iface.net)
    
    # Should succeed despite garbage response
    assert await net.call_endpoint_ping(eid) is None


""" Test that ignore_message_types parameter correctly filters message types
from the endpoint's supported message types list """
async def test_ignore_message_types(dbus, mctpd):
    iface = mctpd.system.interfaces[0]
    dev = mctpd.network.endpoints[0]
    # Configure endpoint to report message types [0, 1, 2, 5, 126]
    dev.types = [0, 1, 2, 5, 126]

    mctp = await mctpd_mctp_iface_obj(dbus, iface)
    static_eid = 12
    start_eid = 13
    ignore_eids = b''  # No EIDs to ignore
    ignore_message_types = bytes([1, 2, 126])  # Ignore message types 1, 2, and 126

    # Assign endpoint with ignore_message_types
    (eid, net, path, new) = await mctp.call_assign_endpoint_static(
        dev.lladdr,
        static_eid,
        start_eid,
        ignore_eids,
        ignore_message_types
    )

    assert eid == static_eid
    assert new

    # Get the endpoint object and query its supported message types
    ep = await mctpd_mctp_endpoint_common_obj(dbus, path)
    query_types = list(await ep.get_supported_message_types())

    # Expected types after filtering: [0, 5]
    # (1, 2, and 126 should be ignored)
    expected_types = [0, 5]
    query_types.sort()
    expected_types.sort()

    assert query_types == expected_types, \
        f"Expected message types {expected_types} but got {query_types}"


""" Test that the LocalEID property is correctly exposed on the endpoint
D-Bus object after AssignEndpointStatic"""
async def test_local_eid_exposed_on_endpoint(dbus, mctpd):
    iface = mctpd.system.interfaces[0]
    dev = mctpd.network.endpoints[0]

    mctp = await mctpd_mctp_iface_obj(dbus, iface)
    static_eid = 12
    start_eid = 13
    ignore_eids = b''
    ignore_message_types = b''

    (eid, net, path, new) = await mctp.call_assign_endpoint_static(
        dev.lladdr,
        static_eid,
        start_eid,
        ignore_eids,
        ignore_message_types
    )

    assert eid == static_eid
    assert new

    # Get the endpoint object and verify LocalEID property
    ep = await mctpd_mctp_endpoint_common_obj(dbus, path)
    local_eid = await ep.get_local_eid()

    # The default system has local EID 8 assigned to the interface
    assert local_eid == 8, \
        f"Expected LocalEID 8 but got {local_eid}"


async def test_assign_dynamic_bridge_eid(dbus, mctpd):
    """Test bridge endpoint dynamic EID assignment and downstream
    endpoint EID allocation

    Tests that:
    - Bridge endpoint can be assigned a dynamic EID
    - Downstream endpoints get contiguous EIDs after bridge's own eid
    """
    iface = mctpd.system.interfaces[0]
    mctp = await mctpd_mctp_iface_obj(dbus, iface)
    ep = mctpd.network.endpoints[0]
    pool_size = 2

    # Set up bridged endpoints as undiscovered EID 0
    for i in range(pool_size):
        br_ep = Endpoint(iface, bytes(), types=[0])
        ep.add_bridged_ep(br_ep)
        mctpd.network.add_endpoint(br_ep)

    # dynamic EID assigment for dev1
    (eid, _, path, new) = await mctp.call_assign_endpoint(ep.lladdr)

    assert new
    assert ep.allocated_pool == (eid + 1, pool_size)


async def test_bridge_ep_conflict_static(dbus, mctpd):
    """Test that static allocations are not permitted, if they would conflict
    with a bridge pool
    """
    iface = mctpd.system.interfaces[0]
    mctp = await mctpd_mctp_iface_obj(dbus, iface)
    ep = mctpd.network.endpoints[0]
    n_bridged = 3

    # add downstream devices
    for i in range(n_bridged):
        br_ep = Endpoint(iface, bytes())
        ep.add_bridged_ep(br_ep)

    (eid, _, path, new) = await mctp.call_assign_endpoint(ep.lladdr)
    assert ep.allocated_pool == (eid + 1, n_bridged)

    # ensure no static assignment can be made from the bridged range
    for i in range(n_bridged):
        dev = Endpoint(iface, bytes([0x30 + i]))
        mctpd.network.add_endpoint(dev)
        with pytest.raises(asyncdbus.errors.DBusError):
            await mctp.call_assign_endpoint_static(
                dev.lladdr, ep.eid + 1 + i, 0, b'', b''
            )

    # ... but we're okay with the EID following
    dev = Endpoint(iface, bytes([0x30 + n_bridged]))
    mctpd.network.add_endpoint(dev)
    static_eid = ep.eid + 1 + n_bridged
    (eid, _, _, _) = await mctp.call_assign_endpoint_static(
        dev.lladdr, static_eid, 0, b'', b''
    )

    assert eid == static_eid


async def test_bridge_ep_conflict_learn(dbus, mctpd):
    """Test that learnt allocations (ie, pre-assigned device EIDs) are not
    permitted, if they would conflict with a bridge pool
    """
    iface = mctpd.system.interfaces[0]
    mctp = await mctpd_mctp_iface_obj(dbus, iface)
    ep = mctpd.network.endpoints[0]
    n_bridged = 3

    # add downstream devices
    for i in range(n_bridged):
        br_ep = Endpoint(iface, bytes())
        ep.add_bridged_ep(br_ep)

    (eid, _, path, new) = await mctp.call_assign_endpoint(ep.lladdr)
    assert ep.allocated_pool == (eid + 1, n_bridged)

    # ensure no learnt assignment can be made from the bridged range
    for i in range(n_bridged):
        dev = Endpoint(iface, bytes([0x30 + i]), eid=ep.eid + 1 + i)
        mctpd.network.add_endpoint(dev)
        with pytest.raises(asyncdbus.errors.DBusError):
            await mctp.call_learn_endpoint(dev.lladdr)

    # ... but we're okay with the EID following
    dev_eid = ep.eid + 1 + n_bridged
    dev = Endpoint(iface, bytes([0x30 + n_bridged]), eid=dev_eid)
    mctpd.network.add_endpoint(dev)
    (eid, _, _, _) = await mctp.call_learn_endpoint(dev.lladdr)

    assert eid == dev_eid


async def test_bridge_ep_conflict_setup(dbus, mctpd):
    """Test that learnt allocations (ie, pre-assigned device EIDs) are not
    permitted through SetupEndpoint, if they would conflict with a bridge pool
    """
    iface = mctpd.system.interfaces[0]
    mctp = await mctpd_mctp_iface_obj(dbus, iface)
    ep = mctpd.network.endpoints[0]
    n_bridged = 3

    # add downstream devices
    for i in range(n_bridged):
        br_ep = Endpoint(iface, bytes())
        ep.add_bridged_ep(br_ep)

    (eid, _, path, new) = await mctp.call_assign_endpoint(ep.lladdr)
    assert ep.allocated_pool == (eid + 1, n_bridged)
    pool_range = range(ep.allocated_pool[0], ep.allocated_pool[1] + 1)

    # ensure no SetupEndpoint assignment can be made from the bridged range;
    # these should get reassigned elsewhere.
    for i in range(n_bridged):
        dev = Endpoint(iface, bytes([0x30 + i]), eid=ep.eid + 1 + i)
        mctpd.network.add_endpoint(dev)
        (eid, _, _, _) = await mctp.call_setup_endpoint(dev.lladdr)
        assert eid not in pool_range


async def test_bridge_setup_reassign(dbus, mctpd):
    """Test that mctpd will reassign a bridge endpoints (pre-configured) EID if
    necessary to satisfy the bridge pool allocation
    """
    iface = mctpd.system.interfaces[0]
    mctp = await mctpd_mctp_iface_obj(dbus, iface)

    # ep: regular endpoint, will conflict with a bridge pool
    ep = mctpd.network.endpoints[0]
    static_eid = 10
    start_eid = 11
    ignore_eids = b''
    ignore_message_types = b''
    (eid, _, _, _) = await mctp.call_assign_endpoint_static(
        ep.lladdr,
        static_eid,
        start_eid,
        ignore_eids,
        ignore_message_types,
    )

    assert eid == static_eid

    # br: our bridge
    conflict_eid = 9
    br = Endpoint(iface, bytes([ep.lladdr[0] + 1]), eid=conflict_eid)
    br.add_bridged_ep(Endpoint(iface, bytes()))
    mctpd.network.add_endpoint(br)

    (eid, _, _, _) = await mctp.call_setup_endpoint(br.lladdr)
    assert eid != conflict_eid
    assert br.allocated_pool is not None
    assert br.allocated_pool[0] == eid + 1


async def test_assign_dynamic_eid_limited_pool(nursery, dbus, sysnet):
    """Test that we truncate the requested pool size to the max_pool_size
    config
    """
    max_pool_size = 1
    config = f"""
    [bus-owner]
    max_pool_size = {max_pool_size}
    """

    mctpd = MctpdWrapper(dbus, sysnet, config=config)
    await mctpd.start_mctpd(nursery)

    iface = mctpd.system.interfaces[0]
    ep = mctpd.network.endpoints[0]
    mctp = await mctpd_mctp_iface_obj(dbus, iface)

    # Set up bridged endpoints as undiscovered EID 0
    for i in range(0, 2):
        br_ep = Endpoint(iface, bytes(), types=[0, 2])
        ep.add_bridged_ep(br_ep)
        mctpd.network.add_endpoint(br_ep)

    # dynamic EID assigment for dev1
    (eid, _, path, new) = await mctp.call_assign_endpoint(ep.lladdr)

    assert new

    bridge_obj = await dbus.get_proxy_object(MCTPD_C, path)
    props_iface = await bridge_obj.get_interface(DBUS_PROPERTIES_I)
    pool_end = await props_iface.call_get(MCTPD_ENDPOINT_BRIDGE_I, "PoolEnd")
    pool_size = pool_end.value - eid
    assert pool_size == max_pool_size

    res = await mctpd.stop_mctpd()
    assert res == 0


async def test_bridge_pool_assign_limited(nursery, dbus, sysnet):
    """Test that a limited pool is assigned if we run out of space for a full
    allocation
    """
    (min_dyn_eid, max_dyn_eid) = (8, 13)
    config = f"""
    [bus-owner]
    dynamic_eid_range = [{min_dyn_eid}, {max_dyn_eid}]
    """

    mctpd = MctpdWrapper(dbus, sysnet, config=config)
    await mctpd.start_mctpd(nursery)

    iface = mctpd.system.interfaces[0]
    ep = mctpd.network.endpoints[0]
    mctp = await mctpd_mctp_iface_obj(dbus, iface)

    # Set up bridged endpoints as undiscovered EID 0; three bridged EPs,
    # which is larger than the available space
    for i in range(0, 3):
        br_ep = Endpoint(iface, bytes(), types=[0, 2])
        ep.add_bridged_ep(br_ep)
        mctpd.network.add_endpoint(br_ep)

    # consume middle eid from the range to dev2
    dev2 = Endpoint(iface, bytes([0x09]))
    mctpd.network.add_endpoint(dev2)
    start_eid = 11
    ignore_eids = b''
    ignore_message_types = b''
    (eid, _, path, new) = await mctp.call_assign_endpoint_static(
        dev2.lladdr, 10,
        start_eid,
        ignore_eids,
        ignore_message_types,
    )
    assert new

    # dynamic EID assigment for dev1
    (eid, _, path, new) = await mctp.call_assign_endpoint(ep.lladdr)
    assert new
    assert ep.allocated_pool is not None
    # we should have the largest range possible; the 8,9-9 range is smaller
    # than the 11,12-13
    assert ep.allocated_pool == (12, 2)

    res = await mctpd.stop_mctpd()
    assert res == 0


async def test_assign_dynamic_eid_allocation_failure(dbus, mctpd):
    """During Allocate Endpoint ID exchange, return completion code failure
    to indicate no pool has been assigned to the bridge
    """

    class BridgeEndpoint(Endpoint):
        async def handle_mctp_control(self, sock, src_addr, msg):
            flags, opcode = msg[0:2]
            if opcode != 0x8:
                return await super().handle_mctp_control(sock, src_addr, msg)
            dst_addr = MCTPSockAddr.for_ep_resp(self, src_addr, sock.addr_ext)

            msg = bytes(
                [
                    flags & 0x1F,  # Rsp
                    0x08,  # opcode: Allocate Endpoint ID
                    0x01,  # cc: failure
                    0x01,  # allocation rejected
                    0x00,  # pool size
                    0x00,  # pool start
                ]
            )
            await sock.send(dst_addr, msg)

    iface = mctpd.system.interfaces[0]
    ep = BridgeEndpoint(iface, bytes([0x1E]))
    mctpd.network.add_endpoint(ep)
    # Set up downstream endpoints as undiscovered EID 0
    for i in range(0, 2):
        br_ep = Endpoint(iface, bytes(), types=[0, 2])
        ep.add_bridged_ep(br_ep)
        mctpd.network.add_endpoint(br_ep)
    mctp = await mctpd_mctp_iface_obj(dbus, iface)

    # dynamic EID assigment for dev1
    (eid, _, path, new) = await mctp.call_assign_endpoint(ep.lladdr)
    assert new
    # Interface should not be present for failed pool allocation
    with pytest.raises(asyncdbus.errors.InterfaceNotFoundError):
        bridge_obj = await dbus.get_proxy_object(MCTPD_C, path)
        await bridge_obj.get_interface(MCTPD_ENDPOINT_BRIDGE_I)


async def test_assign_without_bridge_range(dbus, sysnet, nursery):
    """Test assigning a non-bridge endpoint, when we don't have capacity for
    the speculatively-allocated bridge range
    """
    (dyn_eid_min, dyn_eid_max) = (10, 20)
    max_pool_size = (dyn_eid_max - dyn_eid_min) + 1
    config = f"""
    [bus-owner]
    dynamic_eid_range = [{dyn_eid_min}, {dyn_eid_max}]
    max_pool_size = {max_pool_size}
    """

    mctpd = MctpdWrapper(dbus, sysnet, config=config)
    await mctpd.start_mctpd(nursery)

    iface = mctpd.system.interfaces[0]
    ep = mctpd.network.endpoints[0]

    mctp = await mctpd_mctp_iface_obj(dbus, iface)

    (eid, _, _, _) = await mctp.call_assign_endpoint(ep.lladdr)

    assert eid == dyn_eid_min
    res = await mctpd.stop_mctpd()
    assert res == 0


async def test_bridge_pool_range_limited(dbus, sysnet, nursery):
    """Test that we can still allocate a bridge pool even though we may not have
    the maximum EID range available. The bridge pool's full allocation is still
    possible, since it is smaller than the configured max
    """
    # configure for:
    #     10: bridge A
    #  11-13: bridge A pool
    #     14: bridge B
    #  15-17: bridge B pool
    (dyn_eid_min, dyn_eid_max) = (10, 17)
    bridge_downstreams = 3
    # max pool size would consume more than half of the range, so bridge B
    # cannot be allocated this max
    max_pool_size = 5
    config = f"""
    [bus-owner]
    dynamic_eid_range = [{dyn_eid_min}, {dyn_eid_max}]
    max_pool_size = {max_pool_size}
    """

    mctpd = MctpdWrapper(dbus, sysnet, config=config)
    await mctpd.start_mctpd(nursery)

    iface = mctpd.system.interfaces[0]
    bridges = [
        Endpoint(iface, bytes([0x30])),
        Endpoint(iface, bytes([0x31])),
    ]
    for bridge in bridges:
        mctpd.network.add_endpoint(bridge)
        for i in range(bridge_downstreams):
            bridge.add_bridged_ep(Endpoint(iface, bytes()))

    iface_obj = await mctpd_mctp_iface_obj(dbus, iface)
    for bridge in bridges:
        (eid, _, _, _) = await iface_obj.call_assign_endpoint(bridge.lladdr)
        assert bridge.allocated_pool is not None
        assert bridge.allocated_pool[1] == 3

    res = await mctpd.stop_mctpd()
    assert res == 0


async def test_get_message_types(dbus, mctpd, routed_ep):
    ep = routed_ep

    # Check default response when no responder registered
    cmd = MCTPControlCommand(True, 0, 0x05, bytes([0x00]))
    rsp = await ep.send_control(mctpd.network.mctp_socket, cmd)
    assert rsp.hex(' ') == '00 05 00 01 00'

    # Register spdm responder with a random version
    mctp = await mctpd_mctp_base_iface_obj(dbus)
    await mctp.call_register_type_support(5, [0xF1F2F3F4])

    # Verify invalid msg type causes error
    with pytest.raises(asyncdbus.errors.DBusError) as ex:
        await mctp.call_register_type_support(0x0, [0xF1F2F3F4])
    assert str(ex.value) == "Invalid message type 0"
    with pytest.raises(asyncdbus.errors.DBusError) as ex:
        await mctp.call_register_type_support(0x7E, [0xF1F2F3F4])
    assert str(ex.value) == "Invalid message type 126"

    # Verify get message type response includes spdm
    cmd = MCTPControlCommand(True, 0, 0x05, bytes([0x00]))
    rsp = await ep.send_control(mctpd.network.mctp_socket, cmd)
    assert rsp.hex(' ') == '00 05 00 02 00 05'

    # Verify version passed in dbus call is responded back
    cmd = MCTPControlCommand(True, 0, 0x04, bytes([0x05]))
    rsp = await ep.send_control(mctpd.network.mctp_socket, cmd)
    assert rsp.hex(' ') == '00 04 00 01 f4 f3 f2 f1'


async def test_register_vdm_type_support_empty(mctpd, routed_ep):
    """Test RegisterVDMTypeSupport when no responders are registered"""
    ep = routed_ep

    # Verify error response when no VDM is registered
    cmd = MCTPControlCommand(True, 0, 0x06, bytes([0x00]))
    rsp = await ep.send_control(mctpd.network.mctp_socket, cmd)
    assert rsp.hex(' ') == '00 06 02'


async def test_register_vdm_type_support_pcie_only(dbus, mctpd, routed_ep):
    """Test RegisterVDMTypeSupport when a single PCIe VDM is registered"""
    ep = routed_ep
    mctp = await mctpd_mctp_base_iface_obj(dbus)

    # Register PCIe VDM: format=0x00, VID=0xABCD, command_set=0x0001
    v_type = asyncdbus.Variant('q', 0xABCD)
    await mctp.call_register_vdm_type_support(0x00, v_type, 0x0001)

    # Verify Get Message Type Support response includes PCI VDM type
    cmd = MCTPControlCommand(True, 0, 0x05, bytes([0x00]))
    rsp = await ep.send_control(mctpd.network.mctp_socket, cmd)
    assert rsp.hex(' ') == '00 05 00 02 00 7e'

    # Verify PCIe VDM (selector 0)
    cmd = MCTPControlCommand(True, 0, 0x06, bytes([0x00]))
    rsp = await ep.send_control(mctpd.network.mctp_socket, cmd)
    assert rsp.hex(' ') == '00 06 00 ff 00 ab cd 00 01'

    # Verify error with incorrect selector
    cmd = MCTPControlCommand(True, 0, 0x06, bytes([0x05]))
    rsp = await ep.send_control(mctpd.network.mctp_socket, cmd)
    assert rsp.hex(' ') == '00 06 02'


async def test_register_vdm_type_support_iana_only(dbus, mctpd, routed_ep):
    """Test RegisterVDMTypeSupport when a single IANA VDM is registered"""
    ep = routed_ep
    mctp = await mctpd_mctp_base_iface_obj(dbus)

    # Register IANA VDM: format=0x01, VID=0x1234ABCD, command_set=0x5678
    v_type = asyncdbus.Variant('u', 0x1234ABCD)
    await mctp.call_register_vdm_type_support(0x01, v_type, 0x5678)

    # Verify Get Message Type Support response includes IANA VDM type
    cmd = MCTPControlCommand(True, 0, 0x05, bytes([0x00]))
    rsp = await ep.send_control(mctpd.network.mctp_socket, cmd)
    assert rsp.hex(' ') == '00 05 00 02 00 7f'

    # Verify IANA VDM (selector 0)
    cmd = MCTPControlCommand(True, 0, 0x06, bytes([0x00]))
    rsp = await ep.send_control(mctpd.network.mctp_socket, cmd)
    assert rsp.hex(' ') == '00 06 00 ff 01 12 34 ab cd 56 78'


async def test_register_vdm_type_support_both(dbus, mctpd, routed_ep):
    """Test RegisterVDMTypeSupport when both IANA and PCI types are registered"""
    ep = routed_ep
    mctp = await mctpd_mctp_base_iface_obj(dbus)

    # Register IANA VDM: format=0x01, VID=0x1234ABCD, command_set=0x5678
    v_type = asyncdbus.Variant('u', 0x1234ABCD)
    await mctp.call_register_vdm_type_support(0x01, v_type, 0x5678)

    # Register PCI VDM: format=0x00, VID=0xABCD, command_set=0x5678
    v_type = asyncdbus.Variant('q', 0xABCD)
    await mctp.call_register_vdm_type_support(0x00, v_type, 0x5678)

    # Verify Get Message Type Support response includes both VDM types
    cmd = MCTPControlCommand(True, 0, 0x05, bytes([0x00]))
    rsp = await ep.send_control(mctpd.network.mctp_socket, cmd)
    assert rsp.hex(' ') == '00 05 00 03 00 7e 7f'

    # we assume ordering of IANA vs PCI here, but current mctpd will
    # preserve that.
    # Verify IANA VDM (selector 0)
    cmd = MCTPControlCommand(True, 0, 0x06, bytes([0x00]))
    rsp = await ep.send_control(mctpd.network.mctp_socket, cmd)
    assert rsp.hex(' ') == '00 06 00 01 01 12 34 ab cd 56 78'

    # Verify PCI VDM (selector 1)
    cmd = MCTPControlCommand(True, 0, 0x06, bytes([0x01]))
    rsp = await ep.send_control(mctpd.network.mctp_socket, cmd)
    assert rsp.hex(' ') == '00 06 00 ff 00 ab cd 56 78'


async def test_register_vdm_type_support_dbus_disconnect(mctpd, routed_ep):
    """Test RegisterVDMTypeSupport with dbus disconnect"""
    ep = routed_ep

    # Verify error response when no VDM is registered
    cmd = MCTPControlCommand(True, 0, 0x06, bytes([0x00]))
    rsp = await ep.send_control(mctpd.network.mctp_socket, cmd)
    assert rsp.hex(' ') == '00 06 02'

    async with asyncdbus.MessageBus().connect() as temp_bus:
        mctp = await mctpd_mctp_base_iface_obj(temp_bus)

        # Register PCIe VDM: format=0x00, VID=0xABCD, command_set=1 and 2
        v_type = asyncdbus.Variant('q', 0xABCD)
        await mctp.call_register_vdm_type_support(0x00, v_type, 0x0001)
        await mctp.call_register_vdm_type_support(0x00, v_type, 0x0002)

        # Verify PCIe VDM (selector 0)
        cmd = MCTPControlCommand(True, 0, 0x06, bytes([0x00]))
        rsp = await ep.send_control(mctpd.network.mctp_socket, cmd)
        assert rsp.hex(' ') == '00 06 00 01 00 ab cd 00 01'
        # Verify PCIe VDM (selector 1)
        cmd = MCTPControlCommand(True, 0, 0x06, bytes([0x01]))
        rsp = await ep.send_control(mctpd.network.mctp_socket, cmd)
        assert rsp.hex(' ') == '00 06 00 ff 00 ab cd 00 02'

        # Verify GetMsgType includes VDM
        cmd = MCTPControlCommand(True, 0, 0x05)
        rsp = await ep.send_control(mctpd.network.mctp_socket, cmd)
        assert rsp.hex(' ') == '00 05 00 02 00 7e'

    # Give mctpd a moment to process the disconnection
    await trio.sleep(0.1)

    # Verify VDM type is removed after disconnect
    cmd = MCTPControlCommand(True, 0, 0x06, bytes([0x00]))
    rsp = await ep.send_control(mctpd.network.mctp_socket, cmd)
    assert rsp.hex(' ') == '00 06 02'  # Should be error again

    # Verify GetMsgType has only control command
    cmd = MCTPControlCommand(True, 0, 0x05)
    rsp = await ep.send_control(mctpd.network.mctp_socket, cmd)
    assert rsp.hex(' ') == '00 05 00 01 00'


async def test_register_vdm_type_support_errors(dbus, mctpd):
    """Test RegisterVDMTypeSupport error handling"""
    mctp = await mctpd_mctp_base_iface_obj(dbus)

    # Verify DBus call fails with invalid format 0x02
    v_type = asyncdbus.Variant('q', 0xABCD)
    with pytest.raises(asyncdbus.errors.DBusError) as ex:
        await mctp.call_register_vdm_type_support(0x02, v_type, 0x0001)
    assert "Unsupported VID format" in str(ex.value)

    # Verify incorrect VID type raises error
    v_type = asyncdbus.Variant('u', 0xABCDEF12)
    with pytest.raises(asyncdbus.errors.DBusError) as ex:
        await mctp.call_register_vdm_type_support(0x00, v_type, 0x0001)
    assert "Expected format is PCIe but variant contains" in str(ex.value)

    v_type = asyncdbus.Variant('q', 0xABCD)
    with pytest.raises(asyncdbus.errors.DBusError) as ex:
        await mctp.call_register_vdm_type_support(0x01, v_type, 0x5678)
    assert "Expected format is IANA but variant contains" in str(ex.value)

    # Verify duplicate VDM raises error
    await mctp.call_register_vdm_type_support(0x00, v_type, 0x0001)
    with pytest.raises(asyncdbus.errors.DBusError) as ex:
        await mctp.call_register_vdm_type_support(0x00, v_type, 0x0001)
    assert str(ex.value) == "VDM type already registered"


async def test_query_peer_properties_retry_timeout(nursery, dbus, sysnet):
    class LossyEndpoint(Endpoint):
        """An endpoint object that may drop a specific number (timeout_count)
        of MCTP Control Protocol requests.
        """

        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.timeout_count = 0
            self.timeout_opcode = 0x05  # Get Message Type Support

        async def handle_mctp_control(self, sock, addr, data):
            rq = data[0] & 0x80
            opcode = data[1]
            if rq and opcode == self.timeout_opcode and self.timeout_count:
                self.timeout_count -= 1
                return
            return await super().handle_mctp_control(sock, addr, data)

    # activate mctpd
    mctpd = MctpdWrapper(dbus, sysnet)
    await mctpd.start_mctpd(nursery)

    iface = mctpd.system.interfaces[0]
    mctp = await mctpd_mctp_iface_obj(dbus, iface)

    # define expected message types
    # add a normal endpoint to network
    expected_types = [0, 1, 2]
    ep = LossyEndpoint(iface, bytes([0x1A]), eid=15, types=expected_types)
    mctpd.network.add_endpoint(ep)

    # call setup_endpoint on ep, which will allocate a object path for it
    (eid, net, path, new) = await mctp.call_setup_endpoint(ep.lladdr)

    objep = await mctpd_mctp_endpoint_common_obj(dbus, path)
    objtypes = list(await objep.get_supported_message_types())
    objtypes.sort()
    assert objtypes == expected_types

    ep.lladdr = bytes([0x1B])  # change lladdr to force retry
    ep.timeout_count = 2  # timeout twice before responding

    # call setup_endpoint again, which will trigger query of peer properties
    (eid, net, path, new) = await mctp.call_setup_endpoint(ep.lladdr)

    # timeout twice does not prevent us from getting the correct message types
    objep = await mctpd_mctp_endpoint_common_obj(dbus, path)
    objtypes = list(await objep.get_supported_message_types())
    objtypes.sort()
    assert objtypes == expected_types

    ep.lladdr = bytes([0x1C])  # change lladdr to force retry
    ep.timeout_count = 5  # timeout five times before responding

    # call setup_endpoint again, which will trigger query of peer properties
    (eid, net, path, new) = await mctp.call_setup_endpoint(ep.lladdr)

    # timeout five times does prevent us from getting the correct message types
    objep = await mctpd_mctp_endpoint_common_obj(dbus, path)
    objtypes = list(await objep.get_supported_message_types())
    expected_types = []  # exceeded retry limit, so no types known
    assert objtypes == expected_types

    # exit mctpd
    res = await mctpd.stop_mctpd()
    assert res == 0


async def test_bridged_endpoint_poll(dbus, sysnet, nursery, autojump_clock):
    """Test that we use endpoint poll interval from the config and
    that we discover bridged endpoints via polling
    """

    poll_interval = 2500
    config = f"""
    [bus-owner]
    endpoint_poll_ms = {poll_interval}
    """

    mctpd = MctpdWrapper(dbus, sysnet, config=config)
    await mctpd.start_mctpd(nursery)

    iface = mctpd.system.interfaces[0]
    ep = mctpd.network.endpoints[0]
    mctp = await mctpd_mctp_iface_obj(dbus, iface)

    bridged_ep = [
        Endpoint(iface, bytes(), types=[0, 1]),
        Endpoint(iface, bytes(), types=[0, 1]),
    ]
    for bep in bridged_ep:
        mctpd.network.add_endpoint(bep)
        ep.add_bridged_ep(bep)

    mctp_obj = await dbus.get_proxy_object(MCTPD_C, MCTPD_MCTP_P)
    mctp_objmgr = await mctp_obj.get_interface(DBUS_OBJECT_MANAGER_I)
    endpoint_added = trio.Semaphore(initial_value=0)

    # We expect two bridged endpoints to be discovered
    expected_bridged_eps = len(bridged_ep)
    bridged_endpoints_found = []

    def ep_added(ep_path, content):
        if MCTPD_ENDPOINT_I in content:
            bridged_endpoints_found.append(ep_path)
            endpoint_added.release()

    await mctp_objmgr.on_interfaces_added(ep_added)
    (eid, _, path, new) = await mctp.call_assign_endpoint(ep.lladdr)
    assert new

    # Wait for all expected bridged endpoints to be discovered
    with trio.move_on_after(poll_interval / 1000 * 2) as expected:
        for i in range(expected_bridged_eps):
            await endpoint_added.acquire()

    # Verify we found all expected bridged endpoints
    assert not expected.cancelled_caught, (
        "Timeout waiting for bridged endpoints"
    )
    assert len(bridged_endpoints_found) == expected_bridged_eps

    res = await mctpd.stop_mctpd()
    assert res == 0


async def test_bridged_endpoint_remove(dbus, sysnet, nursery, autojump_clock):
    """Test that all downstream endpoints are removed when the bridge
    endpoint is removed
    """

    poll_interval = 2500
    config = f"""
    [bus-owner]
    endpoint_poll_ms = {poll_interval}
    """

    mctpd = MctpdWrapper(dbus, sysnet, config=config)
    await mctpd.start_mctpd(nursery)

    iface = mctpd.system.interfaces[0]
    ep = mctpd.network.endpoints[0]
    mctp = await mctpd_mctp_iface_obj(dbus, iface)

    bridged_ep = [
        Endpoint(iface, bytes(), types=[0, 1]),
        Endpoint(iface, bytes(), types=[0, 1]),
    ]
    for bep in bridged_ep:
        mctpd.network.add_endpoint(bep)
        ep.add_bridged_ep(bep)

    (eid, _, path, new) = await mctp.call_assign_endpoint(ep.lladdr)
    assert new

    # Wait for the bridged endpoints to be discovered
    await trio.sleep((poll_interval * 2) / 1000)
    removed = trio.Semaphore(initial_value=0)
    removed_eps = []

    # Capture the removed endpoints
    def ep_removed(ep_path, interfaces):
        if MCTPD_ENDPOINT_I in interfaces:
            removed.release()
            removed_eps.append(ep_path)

    mctp_obj = await dbus.get_proxy_object(MCTPD_C, MCTPD_MCTP_P)
    mctp_objmgr = await mctp_obj.get_interface(DBUS_OBJECT_MANAGER_I)
    await mctp_objmgr.on_interfaces_removed(ep_removed)

    # Remove the bridge endpoint
    bridge_obj = await mctpd_mctp_endpoint_control_obj(dbus, path)
    await bridge_obj.call_remove()

    # Assert that all downstream endpoints were removed
    assert len(removed_eps) == (len(bridged_ep) + 1)
    res = await mctpd.stop_mctpd()
    assert res == 0


async def test_bridged_endpoint_poll_stop(
    dbus, sysnet, nursery, autojump_clock
):
    """Test that polling stops once endponit has been discovered"""
    poll_interval = 2500
    config = f"""
    [bus-owner]
    endpoint_poll_ms = {poll_interval}
    """

    mctpd = MctpdWrapper(dbus, sysnet, config=config)
    await mctpd.start_mctpd(nursery)

    iface = mctpd.system.interfaces[0]
    ep = mctpd.network.endpoints[0]
    mctp = await mctpd_mctp_iface_obj(dbus, iface)
    poll_count = 0

    class BridgedEndpoint(Endpoint):
        async def handle_mctp_control(self, sock, src_addr, msg):
            flags, opcode = msg[0:2]
            if opcode == 0x2:  # Get Endpoint ID
                nonlocal poll_count
                poll_count += 1
            return await super().handle_mctp_control(sock, src_addr, msg)

    bridged_ep = BridgedEndpoint(iface, bytes(), types=[0, 1])
    mctpd.network.add_endpoint(bridged_ep)
    ep.add_bridged_ep(bridged_ep)

    (eid, _, path, new) = await mctp.call_assign_endpoint(ep.lladdr)
    assert new

    mctp_obj = await dbus.get_proxy_object(MCTPD_C, MCTPD_MCTP_P)
    mctp_objmgr = await mctp_obj.get_interface(DBUS_OBJECT_MANAGER_I)
    endpoint_added = trio.Semaphore(initial_value=0)
    poll_count_by_discovery = 0

    def ep_added(ep_path, content):
        if MCTPD_ENDPOINT_I in content:
            nonlocal poll_count_by_discovery
            poll_count_by_discovery = poll_count
            endpoint_added.release()

    await mctp_objmgr.on_interfaces_added(ep_added)

    # Wait longer than the poll interval for the bridged endpoint
    # to be discovered
    await trio.sleep(poll_interval / 1000)

    # We should have only poll until the discovery thus count should
    # be the same even after longer wait.
    assert poll_count == poll_count_by_discovery

    res = await mctpd.stop_mctpd()
    assert res == 0


async def test_bridged_endpoint_poll_continue(
    dbus, sysnet, nursery, autojump_clock
):
    """Test that polling continues until the endpoint is discovered"""
    poll_interval = 2500
    config = f"""
    [bus-owner]
    endpoint_poll_ms = {poll_interval}
    """

    mctpd = MctpdWrapper(dbus, sysnet, config=config)
    await mctpd.start_mctpd(nursery)

    iface = mctpd.system.interfaces[0]
    ep = mctpd.network.endpoints[0]
    mctp = await mctpd_mctp_iface_obj(dbus, iface)
    poll_count = 0

    class BridgedEndpoint(Endpoint):
        async def handle_mctp_control(self, sock, src_addr, msg):
            flags, opcode = msg[0:2]
            # dont respond to simiulate device not accessible
            # but increment poll count for the Get Endpoint ID
            if opcode == 0x2:  # Get Endpoint ID
                nonlocal poll_count
                poll_count += 1
            return None

    bridged_ep = BridgedEndpoint(iface, bytes(), types=[0, 1])
    mctpd.network.add_endpoint(bridged_ep)
    ep.add_bridged_ep(bridged_ep)

    (eid, _, path, new) = await mctp.call_assign_endpoint(ep.lladdr)
    assert new

    # Wait for sometime to continue polling
    await trio.sleep(poll_interval / 1000)

    poll_count_before = poll_count
    # Wait more to see if poll count increments
    await trio.sleep(1)
    assert poll_count > poll_count_before

    res = await mctpd.stop_mctpd()
    assert res == 0
