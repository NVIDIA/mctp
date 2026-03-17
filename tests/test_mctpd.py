import pytest
import trio
import uuid
import asyncdbus

from mctp_test_utils import (
    mctpd_mctp_iface_obj,
    mctpd_mctp_network_obj,
    mctpd_mctp_endpoint_common_obj,
    mctpd_mctp_endpoint_control_obj,
    mctpd_service_readiness_obj
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

""" Test that the dbus object tree is sensible: we can introspect all
objects, and that there are no duplicates
"""
async def test_enumerate(dbus, mctpd):
    dups = await _introspect_path_recursive(dbus, '/', set())
    assert not dups


""" Test the SetupEndpoint dbus call

Using the default system & network ojects, call SetupEndpoint on our mock
endpoint. We expect the dbus call to return the endpoint details, and
the new kernel neighbour and route entries.

We have a few things provided by the test infrastructure:

 - dbus is the dbus connection, call the mctpd_mctp_iface_obj helper to
   get the MCTP dbus interface object

 - mctpd is our wrapper for the mctpd process and mock MCTP environment. This
   has two properties that represent external state:

   mctp.system: the local system info - containing MCTP interfaces
     (mctp.system.interfaces), addresses (.addresses), neighbours (.neighbours)
     and routes (.routes). These may be updated by the running mctpd process
     during tests, over the simlated netlink socket.

   mctp.network: the set of remote MCTP endpoints connected to the system. Each
     endpoint has a physical address (.lladdr) and an EID (.eid), and a tiny
     MCTP control protocol implementation, which the mctpd process will
     interact with over simulated AF_MCTP sockets.

By default, we get some minimal defaults for .system and .network:

 - The system has one interface ('mctp0'), assigned local EID 8. This is
   similar to a MCTP-over-i2c interface, in that physical addresses are
   a single byte.

 - The network has one endpoint (lladdr 0x1d) connected to mctp0, with no EID
   assigned. It also has a random UUID, and advertises support for MCTP
   Control Protocol and PLDM (but note that it doesn't actually implement
   any PLDM!).

But these are only defaults; .system and .network can be altered as required
for each test.
"""
async def test_setup_endpoint(dbus, mctpd):
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

""" Test that we correctly handle address conflicts on EID assignment.

We have the following scenario:

 1. A configured peer at physaddr 1, EID A, allocated by mctpd
 2. A non-configured peer at physaddr 2, somehow carrying a default EID also A
 3. Attempt to enumerate physaddr 2

At (3), we should reconfigure the EID to B.
"""
async def test_setup_endpoint_conflict(dbus, mctpd):
    iface = mctpd.system.interfaces[0]

    mctp = await mctpd_mctp_iface_obj(dbus, iface)

    ep1 = mctpd.network.endpoints[0]
    (eid1, _, _, _) = await mctp.call_setup_endpoint(ep1.lladdr)

    # endpoint configured with eid1 already
    ep2 = Endpoint(iface, bytes([0x1e]), eid=eid1)
    mctpd.network.add_endpoint(ep2)

    (eid2, _, _, _) = await mctp.call_setup_endpoint(ep2.lladdr)
    assert eid1 != eid2

""" Test neighbour removal """
async def test_remove_endpoint(dbus, mctpd):
    iface = mctpd.system.interfaces[0]
    ep1 = mctpd.network.endpoints[0]

    mctp = await mctpd_mctp_iface_obj(dbus, iface)
    (_, _, path, _) = await mctp.call_setup_endpoint(ep1.lladdr)

    assert(len(mctpd.system.neighbours) == 1)

    ep = await mctpd_mctp_endpoint_control_obj(dbus, path)

    await ep.call_remove()
    assert(len(mctpd.system.neighbours) == 0)

async def test_recover_endpoint_present(dbus, mctpd):
    iface = mctpd.system.interfaces[0]
    dev = mctpd.network.endpoints[0]
    mctp = await mctpd_mctp_iface_obj(dbus, iface)
    (eid, net, path, new) = await mctp.call_setup_endpoint(dev.lladdr)

    ep = await dbus.get_proxy_object(MCTPD_C, path)
    ep_props = await ep.get_interface(DBUS_PROPERTIES_I)

    recovered = trio.Semaphore(initial_value = 0)
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

async def test_recover_endpoint_removed(dbus, mctpd):
    iface = mctpd.system.interfaces[0]
    dev = mctpd.network.endpoints[0]
    mctp = await dbus.get_proxy_object(MCTPD_C, MCTPD_MCTP_P)
    mctp_iface = await mctpd_mctp_iface_obj(dbus, iface)
    (eid, net, path, new) = await mctp_iface.call_setup_endpoint(dev.lladdr)

    ep = await dbus.get_proxy_object(MCTPD_C, path)
    ep_props = await ep.get_interface(DBUS_PROPERTIES_I)

    degraded = trio.Semaphore(initial_value = 0)
    def ep_connectivity_changed(iface, changed, invalidated):
        if iface == MCTPD_ENDPOINT_I and 'Connectivity' in changed:
            if 'Degraded' == changed['Connectivity'].value:
                degraded.release()

    await ep_props.on_properties_changed(ep_connectivity_changed)

    mctp_objmgr = await mctp.get_interface(DBUS_OBJECT_MANAGER_I)

    removed = trio.Semaphore(initial_value = 0)
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

async def test_recover_endpoint_reset(dbus, mctpd):
    iface = mctpd.system.interfaces[0]
    dev = mctpd.network.endpoints[0]
    mctp = await dbus.get_proxy_object(MCTPD_C, MCTPD_MCTP_P)
    mctp_iface = await mctpd_mctp_iface_obj(dbus, iface)
    (eid, net, path, new) = await mctp_iface.call_setup_endpoint(dev.lladdr)

    ep = await dbus.get_proxy_object(MCTPD_C, path)
    ep_props = await ep.get_interface(DBUS_PROPERTIES_I)

    recovered = trio.Semaphore(initial_value = 0)
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

async def test_recover_endpoint_exchange(dbus, mctpd):
    iface = mctpd.system.interfaces[0]
    dev = mctpd.network.endpoints[0]
    mctp = await dbus.get_proxy_object(MCTPD_C, MCTPD_MCTP_P)
    mctp_iface = await mctpd_mctp_iface_obj(dbus, iface)
    (eid, net, path, new) = await mctp_iface.call_setup_endpoint(dev.lladdr)

    ep = await dbus.get_proxy_object(MCTPD_C, path)
    ep_props = await ep.get_interface(DBUS_PROPERTIES_I)

    degraded = trio.Semaphore(initial_value = 0)
    def ep_connectivity_changed(iface, changed, invalidated):
        if iface == MCTPD_ENDPOINT_I and 'Connectivity' in changed:
            if 'Degraded' == changed['Connectivity'].value:
                degraded.release()

    await ep_props.on_properties_changed(ep_connectivity_changed)

    mctp_objmgr = await mctp.get_interface(DBUS_OBJECT_MANAGER_I)

    removed = trio.Semaphore(initial_value = 0)
    def ep_removed(ep_path, interfaces):
        if ep_path == path and MCTPD_ENDPOINT_I in interfaces:
            removed.release()

    await mctp_objmgr.on_interfaces_removed(ep_removed)

    added = trio.Semaphore(initial_value = 0)
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
    mctpd.network.add_endpoint(Endpoint(dev.iface, dev.lladdr, types = dev.types))

    with trio.move_on_after(2 * MCTPD_TRECLAIM) as expected:
        await added.acquire()
        await removed.acquire()
        await degraded.acquire()

    assert not expected.cancelled_caught

""" Test that we get the correct EID allocated (and the usual route/neigh setup)
on an AssignEndpointStatic call """
async def test_assign_endpoint_static(dbus, mctpd):
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

""" Test that we can repeat an AssignEndpointStatic call with the same static
EID"""
async def test_assign_endpoint_static_allocated(dbus, mctpd):
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

""" Test that we cannot assign a conflicting static EID """
async def test_assign_endpoint_static_conflict(dbus, mctpd):
    iface = mctpd.system.interfaces[0]
    mctp = await mctpd_mctp_iface_obj(dbus, iface)
    dev1 = mctpd.network.endpoints[0]

    dev2 = Endpoint(iface, bytes([0x1e]))
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

""" Test that we cannot re-assign a static EID to an endpoint that already has
a different EID allocated"""
async def test_assign_endpoint_static_varies(dbus, mctpd):
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

""" Test that the mctpd control protocol responder support has support
for a basic Get Endpoint ID command"""
async def test_get_endpoint_id(dbus, mctpd):
    iface = mctpd.system.interfaces[0]
    dev = mctpd.network.endpoints[0]
    mctp = await mctpd_mctp_iface_obj(dbus, iface)
    dev.eid = 12

    await mctpd.system.add_route(mctpd.system.Route(dev.eid, 0, iface = iface))
    await mctpd.system.add_neighbour(
        mctpd.system.Neighbour(iface, dev.lladdr, dev.eid)
    )

    cmd = MCTPControlCommand(True, 0, 0x02)
    rsp = await dev.send_control(mctpd.network.mctp_socket, cmd)

    # command code
    assert rsp[1] == 0x02
    # completion code indicates success
    assert rsp[2] == 0x00
    # EID matches the system
    assert rsp[3] == mctpd.system.addresses[0].eid

""" Test that instance ID is populated correctly on control protocol responses
"""
async def test_response_iid(mctpd):
    peer = mctpd.network.endpoints[0]
    for iid in [0, 1, 30, 31]:
        cmd = MCTPControlCommand(True, iid, 0x02)
        rsp = await peer.send_control(mctpd.network.mctp_socket, cmd)
        assert rsp[0] == iid

""" During a LearnEndpoint's Get Endpoint ID exchange, return a response
from a different command; in this case Get Message Type Support, which happens
to be the same length as a the expected Get Endpoint ID response."""
async def test_learn_endpoint_invalid_response_command(dbus, mctpd):
    class BusyEndpoint(Endpoint):
        async def handle_mctp_control(self, sock, src_addr, msg):
            flags, opcode = msg[0:2]
            if opcode != 2:
                return await super().handle_mctp_control(sock, src_addr, msg)
            dst_addr = MCTPSockAddr.for_ep_resp(self, src_addr, sock.addr_ext)
            msg = bytes([flags & 0x1f, 0x05, 0x00, 0x02, 0x00, 0x01])
            await sock.send(dst_addr, msg)

    iface = mctpd.system.interfaces[0]
    ep = BusyEndpoint(iface, bytes([0x1e]), eid = 15)
    mctpd.network.add_endpoint(ep)
    mctp = await mctpd_mctp_iface_obj(dbus, iface)

    with pytest.raises(asyncdbus.errors.DBusError) as ex:
        rc = await mctp.call_learn_endpoint(ep.lladdr)

    assert str(ex.value) == "Request failed"

""" During a SetupEndpoint's Set Endpoint ID exchange, return a response
that indicates that the EID has been set, but report an invalid (0) EID
in the response."""
async def test_setup_endpoint_invalid_set_eid_response(dbus, mctpd):
    class InvalidEndpoint(Endpoint):
        async def handle_mctp_control(self, sock, src_addr, msg):
            flags, opcode = msg[0:2]
            if opcode != 1:
                return await super().handle_mctp_control(sock, src_addr, msg)
            dst_addr = MCTPSockAddr.for_ep_resp(self, src_addr, sock.addr_ext)
            self.eid = msg[3]
            msg = bytes([
                flags & 0x1f, # Rsp
                0x01, # opcode: Set Endpoint ID
                0x00, # cc: success
                0x00, # assignment accepted, no pool
                0x00, # set EID: invalid
                0x00, # pool size: 0
            ])
            await sock.send(dst_addr, msg)

    iface = mctpd.system.interfaces[0]
    ep = InvalidEndpoint(iface, bytes([0x1e]), eid = 0)
    mctpd.network.add_endpoint(ep)
    mctp = await mctpd_mctp_iface_obj(dbus, iface)

    with pytest.raises(asyncdbus.errors.DBusError) as ex:
        rc = await mctp.call_setup_endpoint(ep.lladdr)

    assert str(ex.value) == "Endpoint returned failure to Set Endpoint ID"

""" During a SetupEndpoint's Set Endpoint ID exchange, return a response
that indicates that the EID has been set, but report a different set EID
in the response."""
async def test_setup_endpoint_vary_set_eid_response(dbus, mctpd):
    class VaryEndpoint(Endpoint):
        async def handle_mctp_control(self, sock, src_addr, msg):
            flags, opcode = msg[0:2]
            if opcode != 1:
                return await super().handle_mctp_control(sock, src_addr, msg)
            dst_addr = MCTPSockAddr.for_ep_resp(self, src_addr, sock.addr_ext)
            self.eid = msg[3] + 1
            msg = bytes([
                flags & 0x1f, # Rsp
                0x01, # opcode: Set Endpoint ID
                0x00, # cc: success
                0x00, # assignment accepted, no pool
                self.eid, # set EID: valid, but not what was assigned
                0x00, # pool size: 0
            ])
            await sock.send(dst_addr, msg)

    iface = mctpd.system.interfaces[0]
    ep = VaryEndpoint(iface, bytes([0x1e]))
    mctpd.network.add_endpoint(ep)
    mctp = await mctpd_mctp_iface_obj(dbus, iface)

    (eid, _, _, _) = await mctp.call_setup_endpoint(ep.lladdr)

    assert eid == ep.eid

""" During a SetupEndpoint's Set Endpoint ID exchange, return a response
that indicates that the EID has been set, but report a different set EID
in the response, which conflicts with another endpoint"""
async def test_setup_endpoint_conflicting_set_eid_response(dbus, mctpd):

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
            msg = bytes([
                flags & 0x1f, # Rsp
                0x01, # opcode: Set Endpoint ID
                0x00, # cc: success
                0x00, # assignment accepted, no pool
                self.eid, # set EID: valid, but not what was assigned
                0x00, # pool size: 0
            ])
            await sock.send(dst_addr, msg)

    iface = mctpd.system.interfaces[0]
    ep1 = mctpd.network.endpoints[0]
    mctp = await mctpd_mctp_iface_obj(dbus, iface)
    (eid1, _, _, _) = await mctp.call_setup_endpoint(ep1.lladdr)
    assert eid1 == ep1.eid

    ep2 = ConflictingEndpoint(iface, bytes([0x1f]), ep1.eid)
    mctpd.network.add_endpoint(ep2)
    with pytest.raises(asyncdbus.errors.DBusError) as ex:
        await mctp.call_setup_endpoint(ep2.lladdr)

    assert "already used" in str(ex.value)

""" Ensure a response with an invalid IID is discarded """
async def test_learn_endpoint_invalid_response_iid(dbus, mctpd):
    class InvalidIIDEndpoint(Endpoint):
        async def handle_mctp_control(self, sock, src_addr, msg):
            # bump IID
            flags = msg[0]
            iid_mask = 0x1d
            flags = (flags & ~iid_mask) | ((flags + 1) & iid_mask)
            msg = bytes([flags]) + msg[1:]
            return await super().handle_mctp_control(sock, src_addr, msg)

    iface = mctpd.system.interfaces[0]
    ep = InvalidIIDEndpoint(iface, bytes([0x1e]), eid = 15)
    mctpd.network.add_endpoint(ep)
    mctp = await mctpd_mctp_iface_obj(dbus, iface)

    with pytest.raises(asyncdbus.errors.DBusError) as ex:
        await mctp.call_learn_endpoint(ep.lladdr)

    assert str(ex.value) == "Request failed"

""" Ensure we're parsing Get Message Type Support responses"""
async def test_query_message_types(dbus, mctpd):
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

""" Network1.LocalEIDs should reflect locally-assigned EID state """
async def test_network_local_eids_single(dbus, mctpd):
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

async def test_concurrent_recovery_setup(dbus, mctpd):
    iface = mctpd.system.interfaces[0]
    mctp_i = await mctpd_mctp_iface_obj(dbus, iface)

    # mctpd context tracks 20 peer objects by default, add and set up 19 so we
    # reach the allocation boundary.
    split = 19
    for i in range(split):
        pep = Endpoint(iface, bytes([0x1e + i]))
        mctpd.network.add_endpoint(pep)
        (_, _, path, _) = await mctp_i.call_setup_endpoint(pep.lladdr)

    # Grab the DBus path for an endpoint that we will cause to be removed from
    # the network through the recovery path. Arbitrarily use the most recent
    # one added
    ep = await dbus.get_proxy_object(MCTPD_C, path)
    ep_props = await ep.get_interface(DBUS_PROPERTIES_I)

    # Set up a match for Connectivity transitioning to Degraded on the endpoint
    # for which we request recovery
    degraded = trio.Semaphore(initial_value = 0)
    def ep_connectivity_changed(iface, changed, invalidated):
        if iface == MCTPD_ENDPOINT_I and 'Connectivity' in changed:
            if 'Degraded' == changed['Connectivity'].value:
                degraded.release()
    await ep_props.on_properties_changed(ep_connectivity_changed)

    # Set up a match for the recovery endpoint object being removed from DBus
    mctp_p = await dbus.get_proxy_object(MCTPD_C, MCTPD_MCTP_P)
    mctp_objmgr = await mctp_p.get_interface(DBUS_OBJECT_MANAGER_I)
    removed = trio.Semaphore(initial_value = 0)
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
    pep = Endpoint(iface, bytes([0x1e + split]))
    mctpd.network.add_endpoint(pep)
    (_, _, _, new) = await mctp_i.call_setup_endpoint(pep.lladdr)
    assert new

    # Verify the recovery process completed gracefully with removal of the
    # endpoint's DBus object
    with trio.move_on_after(2 * MCTPD_TRECLAIM) as expected:
        await removed.acquire()
    assert not expected.cancelled_caught

""" Bridged EP can be discovered via Network1.LearnEndpoint """
async def test_bridged_learn_endpoint(dbus, mctpd):
    iface = mctpd.system.interfaces[0]
    ep = mctpd.network.endpoints[0]
    br_ep = Endpoint(iface, bytes(), eid = 10, types = [0, 2])
    ep.add_bridged_ep(br_ep)
    mctpd.network.add_endpoint(br_ep)

    await mctpd.system.add_route(mctpd.system.Route(br_ep.eid, 1, iface = iface))
    # static neighbour; no gateway route support at present
    await mctpd.system.add_neighbour(mctpd.system.Neighbour(iface, ep.lladdr, br_ep.eid))

    net = await mctpd_mctp_network_obj(dbus, iface.net)
    (path, new) = await net.call_learn_endpoint(br_ep.eid)

    assert path == f'/au/com/codeconstruct/mctp1/networks/1/endpoints/{br_ep.eid}'
    assert new

""" Change a network id, while we have an active endpoint on that net """
async def test_change_network(dbus, mctpd):
    iface = mctpd.system.interfaces[0];
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
    assert str(ex.value) == "Unknown object '/au/com/codeconstruct/mctp1/networks/1'."

    # endpoint should be present under 2/
    ep = await mctpd_mctp_endpoint_common_obj(dbus,
        '/au/com/codeconstruct/mctp1/networks/2/endpoints/8'
    )
    assert ep is not None

""" Delete our only interface """
async def test_del_interface_last(dbus, mctpd):
    iface = mctpd.system.interfaces[0]
    await mctpd.system.del_interface(iface)

    # interface should be gone
    with pytest.raises(asyncdbus.errors.DBusError):
        await mctpd_mctp_iface_obj(dbus, iface)

    # network should be gone
    with pytest.raises(asyncdbus.errors.DBusError):
        await mctpd_mctp_network_obj(dbus, iface.net)

""" Delete an interface with peers attached, ensure all are gone """
async def test_del_interface_with_peers(dbus, mctpd):
    net = mctpd.system.interfaces[0].net
    iface = mctpd.system.Interface(
        'mctp1', 2, net,  bytes([0x10]), 68, 254, True,
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

""" Remove and re-add an interface """
async def test_add_interface(dbus, mctpd):
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
    mctpd.network.add_endpoint(Endpoint(iface, bytes([]), types = [0, 1]))

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
    mctpd.network.add_endpoint(Endpoint(iface, bytes([]), types = [0, 1]))

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

    # Temporarily disable this test
    return

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

""" Test that we use the minimum EID from the dynamic_eid_range config """
async def test_config_dyn_eid_range_min(nursery, dbus, sysnet):
    (min_dyn_eid, max_dyn_eid) = (20, 254)
    config = f"""
    [bus-owner]
    dynamic_eid_range = [{min_dyn_eid}, {max_dyn_eid}]
    """

    # since we're specifying per-test config, we create the wrapper directly
    # rather than using the fixture.
    mctpd = MctpdWrapper(dbus, sysnet, config = config)
    await mctpd.start_mctpd(nursery)

    iface = mctpd.system.interfaces[0]
    ep = mctpd.network.endpoints[0]

    mctp = await mctpd_mctp_iface_obj(dbus, iface)
    (eid, net, path, new) = await mctp.call_setup_endpoint(ep.lladdr)
    assert eid == min_dyn_eid
    assert ep.eid == eid

    res = await mctpd.stop_mctpd()
    assert res == 0

""" Test that we use the maximum EID from the dynamic_eid_range config """
async def test_config_dyn_eid_range_max(nursery, dbus, sysnet):
    (min_dyn_eid, max_dyn_eid) = (20, 21)
    config = f"""
    [bus-owner]
    dynamic_eid_range = [{min_dyn_eid}, {max_dyn_eid}]
    """

    mctpd = MctpdWrapper(dbus, sysnet, config = config)
    await mctpd.start_mctpd(nursery)

    iface = mctpd.system.interfaces[0]
    mctp = await mctpd_mctp_iface_obj(dbus, iface)

    mctpd.network.add_endpoint(Endpoint(iface, bytes([0x01]), types = [0, 1]))
    mctpd.network.add_endpoint(Endpoint(iface, bytes([0x02]), types = [0, 1]))

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

    # Should fail with "Unknown EID"
    assert "Unknown EID" in str(ex.value)

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

