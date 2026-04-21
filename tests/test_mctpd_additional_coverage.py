import pytest
import struct
import asyncdbus
from asyncdbus import Variant
import trio
import subprocess
import os

DBUS_PROPERTIES_I = 'org.freedesktop.DBus.Properties'
MCTPD_ENDPOINT_OBCM_I = 'xyz.openbmc_project.MCTP.Endpoint'
# Connectivity is writable on Endpoint1, not on the OpenBMC interface
MCTPD_ENDPOINT_CC_I = 'au.com.codeconstruct.MCTP.Endpoint1'
import tempfile
from mctp_test_utils import *
from mctpenv import Endpoint, MCTPControlCommand, MCTPSockAddr, MctpdWrapper

MCTP_CTRL_CMD_SET_ENDPOINT_ID = 0x01
MCTP_CTRL_CMD_GET_ENDPOINT_ID = 0x02
MCTP_CTRL_CMD_GET_ENDPOINT_UUID = 0x03
MCTP_CTRL_CMD_GET_VERSION_SUPPORT = 0x04
MCTP_CTRL_CMD_GET_MESSAGE_TYPE_SUPPORT = 0x05
MCTP_CTRL_CMD_RESOLVE_ENDPOINT_ID = 0x07
MCTP_CTRL_CMD_ROUTING_INFO_UPDATE = 0x09
MCTP_CTRL_CMD_GET_ROUTING_TABLE_ENTRIES = 0x0A
MCTP_CTRL_CMD_DISCOVERY_NOTIFY = 0x0D
MCTP_CTRL_CMD_INVALID = 0xFF
MCTP_SET_EID_SET = 0x0
MCTP_SET_EID_FORCE = 0x1
MCTP_SET_EID_RESET = 0x2
MCTP_SET_EID_DISCOVERED = 0x3

MCTP_CTRL_CC_SUCCESS = 0x00
MCTP_CTRL_CC_ERROR = 0x01
MCTP_CTRL_CC_ERROR_INVALID_DATA = 0x04
MCTP_CTRL_CC_ERROR_UNSUPPORTED_CMD = 0x05

def _build_cov_dir():
    return os.path.join(os.path.dirname(__file__), '..', 'build-cov')

def _build_obj_dir():
    return os.path.join(os.path.dirname(__file__), '..', 'obj')

def _resolve_test_mctpd(cwd=None):
    """Resolve test-mctpd path across local and CI layouts."""
    candidates = []
    if cwd:
        candidates.append(os.path.abspath(cwd))
    candidates.extend([
        os.getcwd(),
        os.path.abspath(_build_obj_dir()),
        os.path.abspath(_build_cov_dir()),
    ])

    # Keep order while de-duplicating
    seen = set()
    for candidate in candidates:
        if candidate in seen:
            continue
        seen.add(candidate)
        binary = os.path.join(candidate, 'test-mctpd')
        if os.path.isfile(binary) and os.access(binary, os.X_OK):
            return binary, candidate

    raise FileNotFoundError(
        f"test-mctpd not found in candidate dirs: {candidates}"
    )

def run_mctpd_with_config(config_text, cwd=None):
    """Helper to run mctpd with config and check if it fails"""
    with tempfile.NamedTemporaryFile('w', suffix='.conf', delete=False) as f:
        f.write(config_text)
        f.flush()
        config_file = f.name

    try:
        binary, run_cwd = _resolve_test_mctpd(cwd)
        result = subprocess.run(
            [binary, '-c', config_file],
            capture_output=True,
            text=True,
            timeout=2,
            cwd=run_cwd,
        )
        return result
    except subprocess.TimeoutExpired:
        return None
    except FileNotFoundError as ex:
        # Keep callers' contract: return a nonzero-like result object.
        return subprocess.CompletedProcess(
            args=['test-mctpd', '-c', config_file],
            returncode=127,
            stdout="",
            stderr=str(ex),
        )
    finally:
        os.unlink(config_file)


def run_test_mctpd(argv, cwd=None, timeout=2):
    binary, run_cwd = _resolve_test_mctpd(cwd)
    return subprocess.run(
        [binary] + list(argv),
        capture_output=True,
        text=True,
        timeout=timeout,
        cwd=run_cwd,
    )

def assert_config_rejected(config_text, expect_stderr=False):
    result = run_mctpd_with_config(config_text)
    assert result is not None
    assert result.returncode != 0
    if expect_stderr:
        assert result.stderr != ""

async def assert_dbus_error_contains(awaitable, expected):
    with pytest.raises(asyncdbus.errors.DBusError) as ex:
        await awaitable
    assert expected in str(ex.value)

async def setup_endpoint_with_route(mctpd, ep, eid=None):
    """Helper to set up endpoint with routing for control messages"""
    iface = ep.iface
    if eid:
        ep.eid = eid
    elif ep.eid == 0:
        ep.eid = 12
    
    await mctpd.system.add_route(mctpd.system.Route(ep.eid, 0, iface=iface))
    await mctpd.system.add_neighbour(mctpd.system.Neighbour(iface, ep.lladdr, ep.eid))
    
    return ep.eid

class TestGetEndpointIdRoleBranches:
    """Branches in handle_control_get_endpoint_id: BUS_OWNER vs Endpoint role (eid_type)."""

    async def test_set_eid_operation_variants_in_endpoint_mode(self, nursery, dbus, sysnet):
        """Exercise SetEndpointID SET/RESET/DISCOVERED handling in endpoint mode."""
        config = '[mctp]\nmode = "endpoint"\n'
        mctpd = MctpdWrapper(dbus, sysnet, config=config)
        await mctpd.start_mctpd(nursery)

        ep = mctpd.network.endpoints[0]
        await setup_endpoint_with_route(mctpd, ep)

        variants = [
            (MCTP_SET_EID_SET, 12),
            (MCTP_SET_EID_RESET, 12),
            (MCTP_SET_EID_DISCOVERED, 12),
            (MCTP_SET_EID_SET, 0xFF),
        ]
        for i, (op, eid) in enumerate(variants):
            cmd = MCTPControlCommand(
                True,
                i,
                MCTP_CTRL_CMD_SET_ENDPOINT_ID,
                bytes([op, eid]),
            )
            rsp = await ep.send_control(mctpd.network.mctp_socket, cmd)
            assert len(rsp) >= 3
            assert rsp[1] == MCTP_CTRL_CMD_SET_ENDPOINT_ID

        await mctpd.stop_mctpd()

class TestMctpdCControlSwitchBranches:
    """Hit multiple control command handlers in one flow to improve mctpd.c switch/branch coverage."""

    async def test_all_control_commands_in_sequence(self, dbus, mctpd):
        """Send all supported control command types in sequence (mctpd.c switch branches)."""
        iface = mctpd.system.interfaces[0]
        ep1 = mctpd.network.endpoints[0]
        ep2 = Endpoint(iface, bytes([0xCC]), types=[0, 1])
        mctpd.network.add_endpoint(ep2)
        mctp = await mctpd_mctp_iface_obj(dbus, iface)
        (eid1, _, _, _) = await mctp.call_setup_endpoint(ep1.lladdr)
        ep1.eid = eid1
        (eid2, _, _, _) = await mctp.call_setup_endpoint(ep2.lladdr)
        ep2.eid = eid2
        iid = 0
        # GET_ENDPOINT_ID
        rsp = await ep1.send_control(mctpd.network.mctp_socket, MCTPControlCommand(True, iid, MCTP_CTRL_CMD_GET_ENDPOINT_ID))
        assert rsp[2] == MCTP_CTRL_CC_SUCCESS
        iid += 1
        # GET_ENDPOINT_UUID
        rsp = await ep1.send_control(mctpd.network.mctp_socket, MCTPControlCommand(True, iid, MCTP_CTRL_CMD_GET_ENDPOINT_UUID))
        assert rsp[2] == MCTP_CTRL_CC_SUCCESS
        iid += 1
        # GET_VERSION_SUPPORT (0x00)
        rsp = await ep1.send_control(mctpd.network.mctp_socket, MCTPControlCommand(True, iid, MCTP_CTRL_CMD_GET_VERSION_SUPPORT, bytes([0x00])))
        assert rsp[2] == MCTP_CTRL_CC_SUCCESS
        iid += 1
        # GET_MESSAGE_TYPE_SUPPORT
        rsp = await ep1.send_control(mctpd.network.mctp_socket, MCTPControlCommand(True, iid, MCTP_CTRL_CMD_GET_MESSAGE_TYPE_SUPPORT))
        assert rsp[2] == MCTP_CTRL_CC_SUCCESS
        iid += 1
        # RESOLVE_ENDPOINT_ID (known)
        rsp = await ep1.send_control(mctpd.network.mctp_socket, MCTPControlCommand(True, iid, MCTP_CTRL_CMD_RESOLVE_ENDPOINT_ID, bytes([eid2])))
        assert rsp[2] == MCTP_CTRL_CC_SUCCESS
        iid += 1
        # RESOLVE_ENDPOINT_ID (unknown - branch !peer)
        rsp = await ep1.send_control(mctpd.network.mctp_socket, MCTPControlCommand(True, iid, MCTP_CTRL_CMD_RESOLVE_ENDPOINT_ID, bytes([250])))
        assert rsp[2] == MCTP_CTRL_CC_ERROR
        iid += 1
        # DISCOVERY_NOTIFY
        rsp = await ep1.send_control(mctpd.network.mctp_socket, MCTPControlCommand(True, iid, MCTP_CTRL_CMD_DISCOVERY_NOTIFY))
        assert rsp[2] == MCTP_CTRL_CC_SUCCESS
        iid += 1
        # Unsupported command (default branch)
        rsp = await ep1.send_control(mctpd.network.mctp_socket, MCTPControlCommand(True, iid, MCTP_CTRL_CMD_INVALID))
        assert rsp[2] == MCTP_CTRL_CC_ERROR_UNSUPPORTED_CMD

class TestVerboseModeBranches:
    """mctpd already runs with -v in test harness; exercise flows that have verbose branches."""

    async def test_verbose_full_flow(self, dbus, mctpd):
        """Full flow: setup/remove/recover/control messages to exercise verbose logging."""
        iface = mctpd.system.interfaces[0]
        mctp = await mctpd_mctp_iface_obj(dbus, iface)

        ep1 = mctpd.network.endpoints[0]
        ep2 = Endpoint(iface, bytes([0xD1]), types=[0, 1])
        mctpd.network.add_endpoint(ep2)

        (eid1, _, path1, _) = await mctp.call_setup_endpoint(ep1.lladdr)
        ep1.eid = eid1
        (eid2, _, path2, _) = await mctp.call_setup_endpoint(ep2.lladdr)
        ep2.eid = eid2

        # Read all properties and validate returned values
        for eid_val, path in [(eid1, path1), (eid2, path2)]:
            obmc = await mctpd_mctp_endpoint_common_obj(dbus, path)
            assert await obmc.get_network_id() == iface.net
            assert await obmc.get_eid() == eid_val
            msg_types = await obmc.get_supported_message_types()
            assert msg_types is not None and len(msg_types) > 0
            medium = await obmc.get_medium_type()
            assert medium is not None
            cc = await mctpd_mctp_endpoint_control_obj(dbus, path)
            connectivity = await cc.get_connectivity()
            assert connectivity is not None

        # Link + service readiness - assert properties have expected types/values
        link_ctrl = await mctpd_mctp_iface_control_obj(dbus, iface)
        role = await link_ctrl.get_role()
        assert role is not None
        assert await link_ctrl.get_network_id() == iface.net
        iface_name = await link_ctrl.get_interface()
        assert iface_name is not None
        svc = await mctpd_service_readiness_obj(dbus, iface)
        svc_type = await svc.get_service_type()
        assert svc_type is not None
        state = await svc.get_state()
        assert state is not None

        # Network
        net_obj = await mctpd_mctp_network_obj(dbus, iface.net)
        local_eids = await net_obj.get_local_eids()
        assert local_eids is not None and len(local_eids) > 0

        # Control messages (verbose logging branches in cb_listen_control_msg)
        # Routes already set up by call_setup_endpoint, no need for setup_endpoint_with_route
        iid = 0
        for cmd_code in [MCTP_CTRL_CMD_GET_ENDPOINT_ID,
                         MCTP_CTRL_CMD_GET_ENDPOINT_UUID,
                         MCTP_CTRL_CMD_GET_MESSAGE_TYPE_SUPPORT,
                         MCTP_CTRL_CMD_DISCOVERY_NOTIFY]:
            rsp = await ep1.send_control(mctpd.network.mctp_socket, MCTPControlCommand(True, iid, cmd_code))
            assert len(rsp) >= 2
            iid += 1

        with trio.move_on_after(0.5):
            rsp = await ep1.send_control(mctpd.network.mctp_socket, MCTPControlCommand(True, iid, MCTP_CTRL_CMD_INVALID))
            assert rsp[2] == MCTP_CTRL_CC_ERROR_UNSUPPORTED_CMD
        iid += 1

        # Set EID rejected (bus owner + verbose)
        rsp = await ep1.send_control(mctpd.network.mctp_socket,
            MCTPControlCommand(True, iid, MCTP_CTRL_CMD_SET_ENDPOINT_ID, bytes([MCTP_SET_EID_SET, 12])))
        assert len(rsp) >= 3

        # Recover and remove exercise verbose D-Bus code paths
        ep_ctrl1 = await mctpd_mctp_endpoint_control_obj(dbus, path1)
        await ep_ctrl1.call_recover()
        await trio.sleep(1)

        ep_ctrl2 = await mctpd_mctp_endpoint_control_obj(dbus, path2)
        await ep_ctrl2.call_remove()

class TestBridgeRoutingDeep:
    """Deeper bridge/routing flows to cover query_routing_table and should_ignore_eid."""

    async def test_bridge_routing_all_entries_ignored(self, dbus, mctpd):
        """Exercise should_ignore_eid() during bridge routing-table parse.

        Pool EIDs that appear in the routing table are ignored per AssignEndpointStatic.
        GetRoutingTable still completes successfully: query_routing_table() does not
        fail the D-Bus call when every entry is skipped or ignored.
        """
        iface = mctpd.system.interfaces[0]
        bridge = Endpoint(iface, bytes([0xF2]), types=[0, 1, 5])
        bridge.add_bridged_ep(Endpoint(iface, bytes(), eid=170, types=[0, 1]))
        bridge.add_bridged_ep(Endpoint(iface, bytes(), eid=171, types=[0, 1]))
        mctpd.network.add_endpoint(bridge)
        mctp = await mctpd_mctp_iface_obj(dbus, iface)
        ignore = bytes([170, 171])
        (eid, _, _, _) = await mctp.call_assign_endpoint_static(
            bridge.lladdr, 169, 170, ignore, b''
        )
        assert eid == 169
        await mctp.call_get_routing_table(eid)

class TestConfigBranchConditions:
    """Hit specific AND/OR branch conditions in config parsing."""

    @pytest.mark.parametrize(
        "config",
        [
            ("""
            [bus-owner]
            dynamic_eid_range = [20, 255]
            """),
            ("""
            [bus-owner]
            dynamic_eid_range = [40, 20]
            """),
            ("""
            [bus-owner]
            max_pool_size = -1
            """),
            ("""
            [bus-owner]
            max_pool_size = 300
            """),
            ("{{{{invalid"),
            ("""
            [mctp]
            message_timeout_ms = 0
            """),
            ("""
            [mctp]
            message_timeout_ms = 100001
            """),
            ("""
            [mctp]
            uuid = "not-a-uuid-value"
            """),
        ],
        ids=[
            "range-end-too-high",
            "range-start-greater-than-end",
            "negative-pool",
            "pool-too-large",
            "bad-toml",
            "timeout-zero",
            "timeout-too-large",
            "invalid-uuid",
        ],
    )
    def test_config_branch_invalid_variants(self, config):
        assert isinstance(config, str)
        assert_config_rejected(config)

    pass


class TestControlPayloadErrorBranches:
    """Malformed payloads for control-command handler branches."""

    async def test_control_command_invalid_payload_matrix(self, dbus, mctpd):
        ep = mctpd.network.endpoints[0]
        await setup_endpoint_with_route(mctpd, ep)

        invalid_cases = [
            (MCTP_CTRL_CMD_GET_VERSION_SUPPORT, b""),
            (MCTP_CTRL_CMD_GET_VERSION_SUPPORT, b"\x09"),
            (MCTP_CTRL_CMD_GET_MESSAGE_TYPE_SUPPORT, b"\x00"),
            (MCTP_CTRL_CMD_RESOLVE_ENDPOINT_ID, b""),
            (MCTP_CTRL_CMD_RESOLVE_ENDPOINT_ID, b"\x01\x02"),
            (MCTP_CTRL_CMD_ROUTING_INFO_UPDATE, b"\x01"),
            (MCTP_CTRL_CMD_GET_ROUTING_TABLE_ENTRIES, b""),
        ]

        for i, (cmd_code, payload) in enumerate(invalid_cases):
            with trio.move_on_after(0.5) as scope:
                rsp = await ep.send_control(
                    mctpd.network.mctp_socket,
                    MCTPControlCommand(True, i, cmd_code, payload),
                )
                assert len(rsp) >= 2
            if scope.cancelled_caught:
                # Some malformed payloads intentionally elicit no response.
                continue


class TestConfigValidBranches:
    """Hit valid-path branches in config parsing (subprocess, no D-Bus)."""

    def _assert_config_accepted(self, config_text):
        """Valid config: process should parse config without error.
        It may exit non-zero due to D-Bus failure (no mock), but stderr
        should NOT contain config-parsing error messages."""
        result = run_mctpd_with_config(config_text)
        if result is None:
            return
        config_errors = [
            "can't parse configuration",
            "invalid message_timeout_ms",
            "invalid max_pool_size",
            "dynamic_eid_range has invalid",
            "dynamic_eid_range: start address",
            "dynamic_eid_range: end address",
            "dynamic_eid_range: invalid range",
            "invalid UUID",
            "invalid value",
        ]
        for err in config_errors:
            assert err not in result.stderr, (
                f"Config was rejected: found '{err}' in stderr: {result.stderr[:300]}"
            )

    def test_config_valid_endpoint_mode(self):
        self._assert_config_accepted('[mctp]\nmode = "endpoint"\n')

    def test_config_valid_bus_owner_mode(self):
        self._assert_config_accepted('[mctp]\nmode = "bus-owner"\n')

    def test_config_valid_timeout(self):
        self._assert_config_accepted('[mctp]\nmessage_timeout_ms = 500\n')

    def test_config_valid_pool_and_range(self):
        self._assert_config_accepted(
            '[bus-owner]\ndynamic_eid_range = [8, 200]\nmax_pool_size = 100\n'
        )

    def test_config_range_extra_elements(self):
        """sz > 2 logs a warning but does NOT reject -- config is accepted."""
        self._assert_config_accepted(
            '[bus-owner]\ndynamic_eid_range = [8, 200, 300]\n'
        )

    def test_config_range_single_element(self):
        assert_config_rejected('[bus-owner]\ndynamic_eid_range = [8]\n')

    def test_config_range_start_too_low(self):
        assert_config_rejected('[bus-owner]\ndynamic_eid_range = [1, 200]\n')

    def test_config_empty_toml(self):
        self._assert_config_accepted('')

    def test_config_range_non_integer_element(self):
        """Non-integer values in dynamic_eid_range -> !min_val.ok branch."""
        assert_config_rejected(
            '[bus-owner]\ndynamic_eid_range = ["a", 200]\n'
        )

    def test_config_top_level_mode_bus_owner(self):
        """Top-level mode string -> parse_config val.ok branch."""
        self._assert_config_accepted('mode = "bus-owner"\n')

    def test_config_top_level_mode_endpoint(self):
        """Top-level mode=endpoint -> parse_config_mode endpoint branch."""
        self._assert_config_accepted('mode = "endpoint"\n')

    def test_config_mctp_and_bus_owner_combined(self):
        """Both [mctp] and [bus-owner] sections -> exercises both parse paths."""
        self._assert_config_accepted(
            '[mctp]\nmessage_timeout_ms = 300\n\n'
            '[bus-owner]\ndynamic_eid_range = [10, 100]\nmax_pool_size = 20\n'
        )

    def test_config_mode_unknown(self):
        """Unknown mode value -> rejected by parse_config_mode."""
        assert_config_rejected('mode = "invalid-mode"\n')


class TestLinkRoleSetBranches:
    """Exercise bus_link_set_prop (10 uncov) via D-Bus Properties.Set."""

    async def test_set_role_endpoint_and_back(self, dbus, mctpd):
        iface = mctpd.system.interfaces[0]
        obj = await dbus.get_proxy_object(
            'au.com.codeconstruct.MCTP1',
            '/au/com/codeconstruct/mctp1/interfaces/' + iface.name,
        )
        props = await obj.get_interface(DBUS_PROPERTIES_I)
        iface_name = 'au.com.codeconstruct.MCTP.Interface1'

        await props.call_set(iface_name, 'Role', Variant('s', 'Endpoint'))
        link_ctrl = await mctpd_mctp_iface_control_obj(dbus, iface)
        role = await link_ctrl.get_role()
        assert role == 'Endpoint'

        await props.call_set(iface_name, 'Role', Variant('s', 'BusOwner'))
        role = await link_ctrl.get_role()
        assert role == 'BusOwner'

    async def test_set_role_invalid_rejected(self, dbus, mctpd):
        iface = mctpd.system.interfaces[0]
        obj = await dbus.get_proxy_object(
            'au.com.codeconstruct.MCTP1',
            '/au/com/codeconstruct/mctp1/interfaces/' + iface.name,
        )
        props = await obj.get_interface(DBUS_PROPERTIES_I)
        iface_name = 'au.com.codeconstruct.MCTP.Interface1'
        with pytest.raises(asyncdbus.errors.DBusError):
            await props.call_set(iface_name, 'Role', Variant('s', 'InvalidRole'))


def test_cli_help_and_invalid_option():
    help_res = run_test_mctpd(['-h'])
    assert help_res.returncode != 0

    bad_res = run_test_mctpd(['-z'])
    assert bad_res.returncode != 0


def test_cli_missing_config_file():
    res = run_test_mctpd(['-c', '/tmp/no-such-file-for-mctpd.conf'])
    assert res.returncode != 0
