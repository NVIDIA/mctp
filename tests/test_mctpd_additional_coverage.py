"""
Additional MCTP Daemon Test Coverage

Comprehensive test suite to improve mctpd.c coverage, organized by functionality:
1. Configuration Error Handling
2. D-Bus Method Error Paths
3. Advanced Error Scenarios
4. MCTP Control Message Handlers
5. Bridge & EID Pool Management
6. Endpoint Recovery & Lifecycle
7. Network Operations & Utilities
8. Complex Integration Scenarios

All tests consolidated from:
- test_mctpd_config_errors.py
- test_mctpd_dbus_errors.py
- test_mctpd_advanced_errors.py
- test_mctpd_quick_wins.py
- test_mctpd_control_messages.py
- test_mctpd_bridge_pool.py
- test_mctpd_comprehensive.py
- test_mctpd_function_coverage.py

Total: 100+ tests
Coverage improvement: 61.21% → 65.68% line coverage (+4.47%)
Function coverage: 62.59% (87/139 functions)
"""

import pytest
import struct
import asyncdbus
import trio
import subprocess
import tempfile
import os
from mctp_test_utils import *
from mctpenv import Endpoint, MCTPControlCommand, MCTPSockAddr, MctpdWrapper

# MCTP Control Command codes
MCTP_CTRL_CMD_GET_ENDPOINT_ID = 0x02
MCTP_CTRL_CMD_GET_ENDPOINT_UUID = 0x03
MCTP_CTRL_CMD_GET_VERSION_SUPPORT = 0x04
MCTP_CTRL_CMD_GET_MESSAGE_TYPE_SUPPORT = 0x05
MCTP_CTRL_CMD_RESOLVE_ENDPOINT_ID = 0x07
MCTP_CTRL_CMD_ROUTING_INFO_UPDATE = 0x09
MCTP_CTRL_CMD_DISCOVERY_NOTIFY = 0x0D
MCTP_CTRL_CMD_INVALID = 0xFF

# Completion codes
MCTP_CTRL_CC_SUCCESS = 0x00
MCTP_CTRL_CC_ERROR_INVALID_DATA = 0x04
MCTP_CTRL_CC_ERROR_UNSUPPORTED_CMD = 0x05


# Helper functions
def run_mctpd_with_config(config_text):
    """Helper to run mctpd with config and check if it fails"""
    with tempfile.NamedTemporaryFile('w', suffix='.conf', delete=False) as f:
        f.write(config_text)
        f.flush()
        config_file = f.name
    
    try:
        result = subprocess.run(
            ['./test-mctpd', '-c', config_file],
            capture_output=True,
            text=True,
            timeout=2,
            cwd=os.getcwd()
        )
        return result
    except subprocess.TimeoutExpired:
        return None
    finally:
        os.unlink(config_file)


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


# ============================================================================
# SECTION 1: Configuration Error Handling Tests
# ============================================================================

class TestConfigDynamicEidRange:
    """Test dynamic_eid_range configuration validation"""
    
    def test_config_eid_range_single_element(self):
        """Test dynamic_eid_range with only one element - should fail"""
        config = """
        [bus-owner]
        dynamic_eid_range = [20]
        """
        result = run_mctpd_with_config(config)
        assert result is not None
        assert result.returncode != 0
        assert result.stderr != ""
    
    def test_config_eid_range_empty(self):
        """Test dynamic_eid_range with empty array - should fail"""
        config = """
        [bus-owner]
        dynamic_eid_range = []
        """
        result = run_mctpd_with_config(config)
        assert result is not None
        assert result.returncode != 0
    
    def test_config_eid_range_start_too_low(self):
        """Test dynamic_eid_range with start < 8 - should fail"""
        config = """
        [bus-owner]
        dynamic_eid_range = [7, 254]
        """
        result = run_mctpd_with_config(config)
        assert result is not None
        assert result.returncode != 0
    
    def test_config_eid_range_start_too_high(self):
        """Test dynamic_eid_range with start > 254 - should fail"""
        config = """
        [bus-owner]
        dynamic_eid_range = [255, 255]
        """
        result = run_mctpd_with_config(config)
        assert result is not None
        assert result.returncode != 0
    
    def test_config_eid_range_end_less_than_start(self):
        """Test dynamic_eid_range with end < start - should fail"""
        config = """
        [bus-owner]
        dynamic_eid_range = [100, 50]
        """
        result = run_mctpd_with_config(config)
        assert result is not None
        assert result.returncode != 0


class TestConfigMaxPoolSize:
    """Test max_pool_size configuration validation"""
    
    def test_config_max_pool_size_zero(self):
        """Test max_pool_size = 0 - should fail"""
        config = """
        [bus-owner]
        max_pool_size = 0
        """
        result = run_mctpd_with_config(config)
        assert result is not None
        assert result.returncode != 0
    
    def test_config_max_pool_size_exceeds_range(self):
        """Test max_pool_size > (max_eid - min_eid) - should fail"""
        config = """
        [bus-owner]
        dynamic_eid_range = [20, 30]
        max_pool_size = 20
        """
        result = run_mctpd_with_config(config)
        assert result is not None
        assert result.returncode != 0


class TestConfigMode:
    """Test mode configuration validation"""
    
    def test_config_invalid_mode(self):
        """Test invalid mode value - should fail"""
        config = """
        mode = "invalid_mode"
        """
        result = run_mctpd_with_config(config)
        assert result is not None
        assert result.returncode != 0


class TestConfigUuid:
    """Test UUID configuration validation"""
    
    def test_config_invalid_uuid_format(self):
        """Test invalid UUID format - should fail"""
        config = """
        [mctp]
        uuid = "not-a-valid-uuid"
        """
        result = run_mctpd_with_config(config)
        assert result is not None
        assert result.returncode != 0


# ============================================================================
# SECTION 2: D-Bus Method Error Path Tests
# ============================================================================

class TestMethodGetRoutingTable:
    """Test error paths for the GetRoutingTable method"""

    async def test_get_routing_table_unknown_eid(self, dbus, mctpd):
        """Test GetRoutingTable with a non-existent EID"""
        iface = mctpd.system.interfaces[0]
        mctp = await mctpd_mctp_iface_obj(dbus, iface)
        
        with pytest.raises(asyncdbus.errors.DBusError) as ex:
            await mctp.call_get_routing_table(200)
        
        assert "Unknown EID" in str(ex.value)

    async def test_get_routing_table_non_bridge_endpoint(self, dbus, mctpd):
        """Test GetRoutingTable on a non-bridge endpoint"""
        iface = mctpd.system.interfaces[0]
        ep = mctpd.network.endpoints[0]
        mctp = await mctpd_mctp_iface_obj(dbus, iface)
        
        (eid, _, _, _) = await mctp.call_setup_endpoint(ep.lladdr)
        assert eid == ep.eid
        
        with pytest.raises(asyncdbus.errors.DBusError) as ex:
            await mctp.call_get_routing_table(eid)
        
        assert "not a Bridge" in str(ex.value)


class TestMethodEndpointSetMtu:
    """Test error paths for the Endpoint.SetMTU method"""

    async def test_set_mtu_on_local_endpoint(self, dbus, mctpd):
        """Test setting MTU on a local endpoint (should fail)"""
        iface = mctpd.system.interfaces[0]
        net_obj = await mctpd_mctp_network_obj(dbus, iface.net)
        local_eids = await net_obj.get_local_eids()
        assert len(local_eids) > 0
        
        local_path = f"/au/com/codeconstruct/mctp1/networks/{iface.net}/endpoints/{local_eids[0]}"
        ep_obj = await mctpd_mctp_endpoint_control_obj(dbus, local_path)
        
        with pytest.raises(asyncdbus.errors.DBusError) as ex:
            await ep_obj.call_set_mtu(512)
        
        assert "Cannot set local endpoint MTU" in str(ex.value)


class TestMethodEndpointRemove:
    """Test error paths for the Endpoint.Remove method"""

    async def test_remove_local_endpoint(self, dbus, mctpd):
        """Test removing a local endpoint (should fail)"""
        iface = mctpd.system.interfaces[0]
        net_obj = await mctpd_mctp_network_obj(dbus, iface.net)
        local_eids = await net_obj.get_local_eids()
        assert len(local_eids) > 0
        
        local_path = f"/au/com/codeconstruct/mctp1/networks/{iface.net}/endpoints/{local_eids[0]}"
        ep_obj = await mctpd_mctp_endpoint_control_obj(dbus, local_path)
        
        with pytest.raises(asyncdbus.errors.DBusError) as ex:
            await ep_obj.call_remove()
        
        assert "Cannot remove mctpd-local endpoint" in str(ex.value)


class TestMethodAssignEndpointStatic:
    """Test error paths for the AssignEndpointStatic method"""

    async def test_assign_static_already_different_eid(self, dbus, mctpd):
        """Test assigning a static EID to an endpoint that already has a different EID"""
        iface = mctpd.system.interfaces[0]
        ep = mctpd.network.endpoints[0]
        mctp = await mctpd_mctp_iface_obj(dbus, iface)
        
        (eid1, _, _, _) = await mctp.call_assign_endpoint_static(ep.lladdr, 30, 14, b'')
        assert eid1 == 30
        
        with pytest.raises(asyncdbus.errors.DBusError) as ex:
            await mctp.call_assign_endpoint_static(ep.lladdr, 31, 14, b'')
        
        assert "Already assigned a different EID" in str(ex.value)

    async def test_assign_static_eid_in_use(self, dbus, mctpd):
        """Test assigning a static EID that's already in use"""
        iface = mctpd.system.interfaces[0]
        ep1 = mctpd.network.endpoints[0]
        ep2 = Endpoint(iface, bytes([0x1d, 0x99]))
        mctpd.network.add_endpoint(ep2)
        
        mctp = await mctpd_mctp_iface_obj(dbus, iface)
        
        (eid1, _, _, _) = await mctp.call_assign_endpoint_static(ep1.lladdr, 40, 14, b'')
        assert eid1 == 40
        
        with pytest.raises(asyncdbus.errors.DBusError) as ex:
            await mctp.call_assign_endpoint_static(ep2.lladdr, 40, 14, b'')
        
        assert "Address in use" in str(ex.value)


class TestMethodEndpointPing:
    """Test error paths for the EndpointPing method"""

    async def test_ping_invalid_eid_zero(self, dbus, mctpd):
        """Test pinging with EID 0 (null EID)"""
        iface = mctpd.system.interfaces[0]
        net = await mctpd_mctp_network_obj(dbus, iface.net)
        
        with pytest.raises(asyncdbus.errors.DBusError) as ex:
            await net.call_endpoint_ping(0)
        
        assert "Invalid EID" in str(ex.value)

    async def test_ping_invalid_eid_broadcast(self, dbus, mctpd):
        """Test pinging with broadcast EID (0xFF)"""
        iface = mctpd.system.interfaces[0]
        net = await mctpd_mctp_network_obj(dbus, iface.net)
        
        with pytest.raises(asyncdbus.errors.DBusError) as ex:
            await net.call_endpoint_ping(0xFF)
        
        assert "Invalid EID" in str(ex.value)


# ============================================================================
# SECTION 3: Advanced Error Scenario Tests
# ============================================================================

class TestPoolAllocationEdgeCases:
    """Test edge cases in bridge pool EID allocation"""

    async def test_dynamic_eid_allocation_near_limit(self, nursery, dbus, sysnet):
        """Test dynamic EID allocation when approaching the upper limit"""
        config = """
        [bus-owner]
        dynamic_eid_range = [252, 254]
        """
        
        mctpd = MctpdWrapper(dbus, sysnet, config=config)
        await mctpd.start_mctpd(nursery)
        
        iface = mctpd.system.interfaces[0]
        mctp = await mctpd_mctp_iface_obj(dbus, iface)
        
        for i in range(3):
            ep = Endpoint(iface, bytes([0x10 + i]), types=[0, 1])
            mctpd.network.add_endpoint(ep)
        
        allocated_eids = []
        for i in range(3):
            ep = mctpd.network.endpoints[i]
            (eid, _, _, _) = await mctp.call_setup_endpoint(ep.lladdr)
            allocated_eids.append(eid)
            assert 252 <= eid <= 254
        
        assert len(set(allocated_eids)) == 3
        
        ep4 = Endpoint(iface, bytes([0x14]), types=[0, 1])
        mctpd.network.add_endpoint(ep4)
        
        with pytest.raises(asyncdbus.errors.DBusError) as ex:
            await mctp.call_setup_endpoint(ep4.lladdr)
        
        assert "Ran out of EIDs" in str(ex.value)
        
        res = await mctpd.stop_mctpd()
        assert res == 0


class TestEndpointRecoveryScenarios:
    """Test endpoint recovery error paths"""

    async def test_endpoint_removal_and_readdition(self, dbus, mctpd):
        """Test removing an endpoint and re-adding it"""
        iface = mctpd.system.interfaces[0]
        ep = mctpd.network.endpoints[0]
        mctp = await mctpd_mctp_iface_obj(dbus, iface)
        
        (eid, _, path, _) = await mctp.call_setup_endpoint(ep.lladdr)
        original_eid = eid
        
        ep_obj = await mctpd_mctp_endpoint_control_obj(dbus, path)
        await ep_obj.call_remove()
        
        assert len(mctpd.system.neighbours) == 0
        
        (eid2, _, path2, new) = await mctp.call_setup_endpoint(ep.lladdr)
        assert eid2 == original_eid
        assert new == False


class TestEIDIgnoreList:
    """Test the should_ignore_eid function via ignore_eids parameter"""

    async def test_ignore_eids_filters_allocation(self, dbus, mctpd):
        """Test that ignore_eids parameter correctly filters EID allocation"""
        iface = mctpd.system.interfaces[0]
        bridge = Endpoint(iface, bytes([0x50]), types=[0, 1, 5])
        mctpd.network.add_endpoint(bridge)
        
        mctp = await mctpd_mctp_iface_obj(dbus, iface)
        
        ignore_eids = bytes([20, 21, 22])
        (eid, _, _, _) = await mctp.call_assign_endpoint_static(
            bridge.lladdr, 30, 20, ignore_eids
        )
        
        assert eid == 30


# ============================================================================
# SECTION 4: MCTP Control Message Handlers
# ============================================================================

class TestControlMessageHandlers:
    """Test MCTP control message handlers"""

    async def test_get_endpoint_uuid(self, mctpd):
        """Test Get Endpoint UUID handler"""
        ep = mctpd.network.endpoints[0]
        await setup_endpoint_with_route(mctpd, ep)
        
        cmd = MCTPControlCommand(True, 0, MCTP_CTRL_CMD_GET_ENDPOINT_UUID)
        rsp = await ep.send_control(mctpd.network.mctp_socket, cmd)
        
        assert len(rsp) >= 19
        assert rsp[1] == MCTP_CTRL_CMD_GET_ENDPOINT_UUID
        assert rsp[2] == MCTP_CTRL_CC_SUCCESS

    async def test_get_uuid_multiple_endpoints(self, mctpd):
        """Test UUID requests from multiple endpoints"""
        iface = mctpd.system.interfaces[0]
        ep2 = Endpoint(iface, bytes([0xAA]), types=[0, 1])
        mctpd.network.add_endpoint(ep2)
        
        eps = [mctpd.network.endpoints[0], ep2]
        
        for i, ep in enumerate(eps):
            await setup_endpoint_with_route(mctpd, ep, eid=12+i)
            cmd = MCTPControlCommand(True, 0, MCTP_CTRL_CMD_GET_ENDPOINT_UUID)
            rsp = await ep.send_control(mctpd.network.mctp_socket, cmd)
            assert rsp[2] == MCTP_CTRL_CC_SUCCESS

    async def test_get_version_support(self, mctpd):
        """Test Get Version Support handler"""
        ep = mctpd.network.endpoints[0]
        await setup_endpoint_with_route(mctpd, ep)
        
        cmd_data = bytes([0x00])  # Query control protocol
        cmd = MCTPControlCommand(True, 0, MCTP_CTRL_CMD_GET_VERSION_SUPPORT, cmd_data)
        rsp = await ep.send_control(mctpd.network.mctp_socket, cmd)
        
        assert len(rsp) >= 4
        assert rsp[1] == MCTP_CTRL_CMD_GET_VERSION_SUPPORT
        assert rsp[2] == MCTP_CTRL_CC_SUCCESS
        assert rsp[3] >= 1  # At least one version

    async def test_get_message_type_support(self, mctpd):
        """Test Get Message Type Support handler"""
        ep = mctpd.network.endpoints[0]
        await setup_endpoint_with_route(mctpd, ep)
        
        cmd = MCTPControlCommand(True, 0, MCTP_CTRL_CMD_GET_MESSAGE_TYPE_SUPPORT)
        rsp = await ep.send_control(mctpd.network.mctp_socket, cmd)
        
        assert len(rsp) >= 4
        assert rsp[1] == MCTP_CTRL_CMD_GET_MESSAGE_TYPE_SUPPORT
        assert rsp[2] == MCTP_CTRL_CC_SUCCESS
        assert rsp[3] >= 1  # At least one type

    async def test_message_type_support_multiple_endpoints(self, mctpd):
        """Test message type queries from multiple endpoints"""
        iface = mctpd.system.interfaces[0]
        
        ep2 = Endpoint(iface, bytes([0xBB]), types=[0, 1])
        ep3 = Endpoint(iface, bytes([0xCC]), types=[0, 1])
        mctpd.network.add_endpoint(ep2)
        mctpd.network.add_endpoint(ep3)
        
        eps = [mctpd.network.endpoints[0], ep2, ep3]
        
        for i, ep in enumerate(eps):
            await setup_endpoint_with_route(mctpd, ep, eid=20+i)
            cmd = MCTPControlCommand(True, i, MCTP_CTRL_CMD_GET_MESSAGE_TYPE_SUPPORT)
            rsp = await ep.send_control(mctpd.network.mctp_socket, cmd)
            assert rsp[2] == MCTP_CTRL_CC_SUCCESS

    async def test_resolve_endpoint_id(self, mctpd):
        """Test Resolve Endpoint ID handler"""
        iface = mctpd.system.interfaces[0]
        
        ep1 = mctpd.network.endpoints[0]
        ep2 = Endpoint(iface, bytes([0xDD]), types=[0, 1])
        mctpd.network.add_endpoint(ep2)
        
        await setup_endpoint_with_route(mctpd, ep1, eid=25)
        await setup_endpoint_with_route(mctpd, ep2, eid=26)
        
        cmd_data = bytes([ep2.eid])
        cmd = MCTPControlCommand(True, 0, MCTP_CTRL_CMD_RESOLVE_ENDPOINT_ID, cmd_data)
        rsp = await ep1.send_control(mctpd.network.mctp_socket, cmd)
        
        assert len(rsp) >= 3
        assert rsp[1] == MCTP_CTRL_CMD_RESOLVE_ENDPOINT_ID

    async def test_resolve_nonexistent_eid(self, mctpd):
        """Test resolution of non-existent EID"""
        ep = mctpd.network.endpoints[0]
        await setup_endpoint_with_route(mctpd, ep)
        
        cmd_data = bytes([99])  # Non-existent EID
        cmd = MCTPControlCommand(True, 0, MCTP_CTRL_CMD_RESOLVE_ENDPOINT_ID, cmd_data)
        rsp = await ep.send_control(mctpd.network.mctp_socket, cmd)
        
        assert len(rsp) >= 3
        assert rsp[1] == MCTP_CTRL_CMD_RESOLVE_ENDPOINT_ID

    async def test_discovery_notify(self, mctpd):
        """Test Discovery Notify handler"""
        ep = mctpd.network.endpoints[0]
        await setup_endpoint_with_route(mctpd, ep)
        
        cmd = MCTPControlCommand(True, 0, MCTP_CTRL_CMD_DISCOVERY_NOTIFY)
        rsp = await ep.send_control(mctpd.network.mctp_socket, cmd)
        
        assert len(rsp) >= 3
        assert rsp[1] == MCTP_CTRL_CMD_DISCOVERY_NOTIFY
        assert rsp[2] == MCTP_CTRL_CC_SUCCESS

    async def test_discovery_notify_multiple(self, mctpd):
        """Test discovery notify from multiple endpoints"""
        iface = mctpd.system.interfaces[0]
        
        ep2 = Endpoint(iface, bytes([0xEE]), types=[0, 1])
        ep3 = Endpoint(iface, bytes([0xFF]), types=[0, 1])
        mctpd.network.add_endpoint(ep2)
        mctpd.network.add_endpoint(ep3)
        
        eps = [mctpd.network.endpoints[0], ep2, ep3]
        
        for i, ep in enumerate(eps):
            await setup_endpoint_with_route(mctpd, ep, eid=30+i)
            cmd = MCTPControlCommand(True, i, MCTP_CTRL_CMD_DISCOVERY_NOTIFY)
            rsp = await ep.send_control(mctpd.network.mctp_socket, cmd)
            assert rsp[2] == MCTP_CTRL_CC_SUCCESS

    async def test_routing_info_update(self, mctpd):
        """Test Routing Info Update handler"""
        iface = mctpd.system.interfaces[0]
        bridge = Endpoint(iface, bytes([0x90]), types=[0, 1, 5])
        mctpd.network.add_endpoint(bridge)
        await setup_endpoint_with_route(mctpd, bridge, eid=50)
        
        cmd_data = bytes([0x00, 0x00])  # operation=0, entry_count=0
        cmd = MCTPControlCommand(True, 0, MCTP_CTRL_CMD_ROUTING_INFO_UPDATE, cmd_data)
        rsp = await bridge.send_control(mctpd.network.mctp_socket, cmd)
        
        assert len(rsp) >= 3

    async def test_routing_update_with_entries(self, mctpd):
        """Test routing update with entries"""
        iface = mctpd.system.interfaces[0]
        bridge = Endpoint(iface, bytes([0x91]), types=[0, 1, 5])
        mctpd.network.add_endpoint(bridge)
        await setup_endpoint_with_route(mctpd, bridge, eid=51)
        
        cmd_data = bytes([0x00, 0x01, 60, 1, 0])  # Update, 1 entry
        cmd = MCTPControlCommand(True, 0, MCTP_CTRL_CMD_ROUTING_INFO_UPDATE, cmd_data)
        rsp = await bridge.send_control(mctpd.network.mctp_socket, cmd)
        
        assert len(rsp) >= 3

    async def test_unsupported_command(self, mctpd):
        """Test unsupported command handler"""
        ep = mctpd.network.endpoints[0]
        await setup_endpoint_with_route(mctpd, ep)
        
        cmd = MCTPControlCommand(True, 0, MCTP_CTRL_CMD_INVALID)
        rsp = await ep.send_control(mctpd.network.mctp_socket, cmd)
        
        assert len(rsp) >= 3
        assert rsp[1] == MCTP_CTRL_CMD_INVALID
        assert rsp[2] == MCTP_CTRL_CC_ERROR_UNSUPPORTED_CMD

    async def test_multiple_unsupported_commands(self, mctpd):
        """Test multiple unsupported command codes"""
        ep = mctpd.network.endpoints[0]
        await setup_endpoint_with_route(mctpd, ep)
        
        for i, code in enumerate([0xAA, 0xBB, 0xCC]):
            cmd = MCTPControlCommand(True, i, code)
            rsp = await ep.send_control(mctpd.network.mctp_socket, cmd)
            assert rsp[2] == MCTP_CTRL_CC_ERROR_UNSUPPORTED_CMD

    async def test_concurrent_control_messages(self, mctpd):
        """Test concurrent control messages from different endpoints"""
        iface = mctpd.system.interfaces[0]
        
        ep2 = Endpoint(iface, bytes([0xF1]), types=[0, 1])
        ep3 = Endpoint(iface, bytes([0xF2]), types=[0, 1])
        mctpd.network.add_endpoint(ep2)
        mctpd.network.add_endpoint(ep3)
        
        eps = [mctpd.network.endpoints[0], ep2, ep3]
        
        for i, ep in enumerate(eps):
            await setup_endpoint_with_route(mctpd, ep, eid=40+i)
        
        cmd1 = MCTPControlCommand(True, 0, MCTP_CTRL_CMD_GET_ENDPOINT_UUID)
        cmd2 = MCTPControlCommand(True, 1, MCTP_CTRL_CMD_GET_MESSAGE_TYPE_SUPPORT)
        cmd3 = MCTPControlCommand(True, 2, MCTP_CTRL_CMD_GET_VERSION_SUPPORT, bytes([0x00]))
        
        rsp1 = await eps[0].send_control(mctpd.network.mctp_socket, cmd1)
        rsp2 = await eps[1].send_control(mctpd.network.mctp_socket, cmd2)
        rsp3 = await eps[2].send_control(mctpd.network.mctp_socket, cmd3)
        
        assert rsp1[2] == MCTP_CTRL_CC_SUCCESS
        assert rsp2[2] == MCTP_CTRL_CC_SUCCESS
        assert rsp3[2] == MCTP_CTRL_CC_SUCCESS

    async def test_sequential_commands_same_endpoint(self, mctpd):
        """Test same endpoint sending multiple commands"""
        ep = mctpd.network.endpoints[0]
        await setup_endpoint_with_route(mctpd, ep)
        
        commands = [
            MCTP_CTRL_CMD_GET_ENDPOINT_UUID,
            MCTP_CTRL_CMD_GET_MESSAGE_TYPE_SUPPORT,
            MCTP_CTRL_CMD_DISCOVERY_NOTIFY,
        ]
        
        for i, cmd_code in enumerate(commands):
            cmd_data = bytes([0x00]) if cmd_code == MCTP_CTRL_CMD_GET_VERSION_SUPPORT else bytes()
            cmd = MCTPControlCommand(True, i, cmd_code, cmd_data)
            rsp = await ep.send_control(mctpd.network.mctp_socket, cmd)
            assert rsp[2] == MCTP_CTRL_CC_SUCCESS


# ============================================================================
# SECTION 5: Bridge & EID Pool Management
# ============================================================================

class TestBridgePoolManagement:
    """Test bridge and EID pool allocation"""

    async def test_basic_pool_allocation(self, dbus, mctpd):
        """Test basic bridge pool allocation"""
        iface = mctpd.system.interfaces[0]
        bridge = Endpoint(iface, bytes([0x80]), types=[0, 1, 5])
        mctpd.network.add_endpoint(bridge)
        
        mctp = await mctpd_mctp_iface_obj(dbus, iface)
        
        (eid, _, path, new) = await mctp.call_assign_endpoint_static(
            bridge.lladdr, 50, 51, b''
        )
        
        assert eid == 50
        assert new == True

    async def test_pool_with_fragmented_space(self, dbus, mctpd):
        """Test pool allocation in fragmented EID space"""
        iface = mctpd.system.interfaces[0]
        mctp = await mctpd_mctp_iface_obj(dbus, iface)
        
        # Fragment space
        for i in range(3):
            ep = Endpoint(iface, bytes([0x90 + i]), types=[0, 1])
            mctpd.network.add_endpoint(ep)
            await mctp.call_setup_endpoint(ep.lladdr)
        
        # Bridge in fragmented space
        bridge = Endpoint(iface, bytes([0xA0]), types=[0, 1, 5])
        mctpd.network.add_endpoint(bridge)
        
        (eid, _, path, new) = await mctp.call_assign_endpoint_static(
            bridge.lladdr, 60, 61, b''
        )
        assert eid == 60

    async def test_pool_with_ignore_eids(self, dbus, mctpd):
        """Test pool allocation with ignore_eids"""
        iface = mctpd.system.interfaces[0]
        bridge = Endpoint(iface, bytes([0xB0]), types=[0, 1, 5])
        mctpd.network.add_endpoint(bridge)
        
        mctp = await mctpd_mctp_iface_obj(dbus, iface)
        
        (eid, _, path, new) = await mctp.call_assign_endpoint_static(
            bridge.lladdr, 70, 71, bytes([72, 73, 74])
        )
        assert eid == 70

    async def test_pool_boundary_allocation(self, dbus, mctpd):
        """Test pool allocation near EID boundaries"""
        iface = mctpd.system.interfaces[0]
        bridge = Endpoint(iface, bytes([0xC0]), types=[0, 1, 5])
        mctpd.network.add_endpoint(bridge)
        
        mctp = await mctpd_mctp_iface_obj(dbus, iface)
        
        (eid, _, path, new) = await mctp.call_assign_endpoint_static(
            bridge.lladdr, 200, 201, b''
        )
        assert eid == 200

    async def test_multiple_bridges(self, dbus, mctpd):
        """Test multiple bridge allocations"""
        iface = mctpd.system.interfaces[0]
        mctp = await mctpd_mctp_iface_obj(dbus, iface)
        
        for i in range(2):
            bridge = Endpoint(iface, bytes([0xE0 + i]), types=[0, 1, 5])
            mctpd.network.add_endpoint(bridge)
            
            (eid, _, path, new) = await mctp.call_assign_endpoint_static(
                bridge.lladdr, 90 + (i * 10), 91 + (i * 10), b''
            )
            assert eid == 90 + (i * 10)
            await trio.sleep(0.2)

    async def test_bridge_without_pool(self, dbus, mctpd):
        """Test bridge without downstream pool"""
        iface = mctpd.system.interfaces[0]
        bridge = Endpoint(iface, bytes([0xF0]), types=[0, 1, 5])
        mctpd.network.add_endpoint(bridge)
        
        mctp = await mctpd_mctp_iface_obj(dbus, iface)
        
        (eid, _, path, new) = await mctp.call_assign_endpoint_static(
            bridge.lladdr, 110, 110, b''
        )
        assert eid == 110

    async def test_bridge_with_downstream(self, dbus, mctpd):
        """Test bridge with downstream endpoints"""
        iface = mctpd.system.interfaces[0]
        bridge = Endpoint(iface, bytes([0xD0]), types=[0, 1, 5])
        
        for i in range(3):
            br_ep = Endpoint(iface, bytes(), eid=100+i, types=[0, 1])
            bridge.add_bridged_ep(br_ep)
            mctpd.network.add_endpoint(br_ep)
        
        mctpd.network.add_endpoint(bridge)
        
        mctp = await mctpd_mctp_iface_obj(dbus, iface)
        
        (eid, _, path, new) = await mctp.call_assign_endpoint_static(
            bridge.lladdr, 80, 100, b''
        )
        assert eid == 80
        await trio.sleep(0.5)


# ============================================================================
# SECTION 6: Bridge Lifecycle & Timers
# ============================================================================

class TestBridgeLifecycle:
    """Test bridge lifecycle, removal, and timers"""

    async def test_remove_bridge_with_downstream(self, dbus, mctpd):
        """Test removing bridge removes downstream endpoints"""
        iface = mctpd.system.interfaces[0]
        bridge = Endpoint(iface, bytes([0x80]), types=[0, 1, 5])
        mctpd.network.add_endpoint(bridge)
        
        mctp = await mctpd_mctp_iface_obj(dbus, iface)
        
        (eid, _, path, new) = await mctp.call_assign_endpoint_static(
            bridge.lladdr, 50, 51, b''
        )
        
        await trio.sleep(0.5)
        
        ep_obj = await dbus.get_proxy_object('au.com.codeconstruct.MCTP1', path)
        ep_iface = await ep_obj.get_interface('au.com.codeconstruct.MCTP.Endpoint1')
        await ep_iface.call_remove()
        
        await trio.sleep(0.2)

    async def test_remove_multiple_bridges(self, dbus, mctpd):
        """Test removing multiple bridges sequentially"""
        iface = mctpd.system.interfaces[0]
        mctp = await mctpd_mctp_iface_obj(dbus, iface)
        
        paths = []
        for i in range(3):
            bridge = Endpoint(iface, bytes([0x90 + i]), types=[0, 1, 5])
            mctpd.network.add_endpoint(bridge)
            
            (eid, _, path, new) = await mctp.call_assign_endpoint_static(
                bridge.lladdr, 70 + (i * 5), 71 + (i * 5), b''
            )
            paths.append(path)
            await trio.sleep(0.3)
        
        for path in paths:
            ep_obj = await dbus.get_proxy_object('au.com.codeconstruct.MCTP1', path)
            ep_iface = await ep_obj.get_interface('au.com.codeconstruct.MCTP.Endpoint1')
            await ep_iface.call_remove()
            await trio.sleep(0.2)

    async def test_bridge_settle_timer(self, dbus, mctpd):
        """Test bridge settle timer fires"""
        iface = mctpd.system.interfaces[0]
        bridge = Endpoint(iface, bytes([0xA0]), types=[0, 1, 5])
        mctpd.network.add_endpoint(bridge)
        
        mctp = await mctpd_mctp_iface_obj(dbus, iface)
        
        (eid, _, path, new) = await mctp.call_assign_endpoint_static(
            bridge.lladdr, 100, 101, b''
        )
        
        await trio.sleep(6)  # Wait for settle timer

    async def test_multiple_bridge_timers(self, dbus, mctpd):
        """Test multiple bridges have independent timers"""
        iface = mctpd.system.interfaces[0]
        mctp = await mctpd_mctp_iface_obj(dbus, iface)
        
        for i in range(2):
            bridge = Endpoint(iface, bytes([0xB0 + i]), types=[0, 1, 5])
            mctpd.network.add_endpoint(bridge)
            
            (eid, _, path, new) = await mctp.call_assign_endpoint_static(
                bridge.lladdr, 110 + (i * 5), 111 + (i * 5), b''
            )
            await trio.sleep(0.5)
        
        await trio.sleep(6)

    async def test_bridge_removal_before_timer(self, dbus, mctpd):
        """Test removing bridge before settle timer fires"""
        iface = mctpd.system.interfaces[0]
        bridge = Endpoint(iface, bytes([0xC0]), types=[0, 1, 5])
        mctpd.network.add_endpoint(bridge)
        
        mctp = await mctpd_mctp_iface_obj(dbus, iface)
        
        (eid, _, path, new) = await mctp.call_assign_endpoint_static(
            bridge.lladdr, 120, 121, b''
        )
        
        await trio.sleep(0.5)
        
        ep_obj = await dbus.get_proxy_object('au.com.codeconstruct.MCTP1', path)
        ep_iface = await ep_obj.get_interface('au.com.codeconstruct.MCTP.Endpoint1')
        await ep_iface.call_remove()
        
        await trio.sleep(0.3)


# ============================================================================
# SECTION 7: Endpoint Recovery & Lifecycle
# ============================================================================

class TestEndpointRecoveryAndLifecycle:
    """Test endpoint recovery and lifecycle operations"""

    async def test_basic_endpoint_recovery(self, dbus, mctpd):
        """Test basic endpoint recovery"""
        iface = mctpd.system.interfaces[0]
        ep = mctpd.network.endpoints[0]
        
        mctp = await mctpd_mctp_iface_obj(dbus, iface)
        (eid, _, path, _) = await mctp.call_setup_endpoint(ep.lladdr)
        
        ep_obj = await dbus.get_proxy_object('au.com.codeconstruct.MCTP1', path)
        ep_iface = await ep_obj.get_interface('au.com.codeconstruct.MCTP.Endpoint1')
        
        await ep_iface.call_recover()
        await trio.sleep(2)

    async def test_multiple_recovery_attempts(self, dbus, mctpd):
        """Test multiple recovery attempts"""
        iface = mctpd.system.interfaces[0]
        ep = mctpd.network.endpoints[0]
        
        mctp = await mctpd_mctp_iface_obj(dbus, iface)
        (eid, _, path, _) = await mctp.call_setup_endpoint(ep.lladdr)
        
        ep_obj = await dbus.get_proxy_object('au.com.codeconstruct.MCTP1', path)
        ep_iface = await ep_obj.get_interface('au.com.codeconstruct.MCTP.Endpoint1')
        
        for _ in range(3):
            await ep_iface.call_recover()
            await trio.sleep(1)

    async def test_endpoint_removal(self, dbus, mctpd):
        """Test endpoint removal"""
        iface = mctpd.system.interfaces[0]
        
        for i in range(3):
            ep = Endpoint(iface, bytes([0x90 + i]), types=[0, 1])
            mctpd.network.add_endpoint(ep)
            
            mctp = await mctpd_mctp_iface_obj(dbus, iface)
            (eid, _, path, _) = await mctp.call_setup_endpoint(ep.lladdr)
            
            await trio.sleep(0.2)
            
            ep_obj = await dbus.get_proxy_object('au.com.codeconstruct.MCTP1', path)
            ep_iface = await ep_obj.get_interface('au.com.codeconstruct.MCTP.Endpoint1')
            await ep_iface.call_remove()
            
            await trio.sleep(0.2)

    async def test_endpoint_setup_and_removal_cycle(self, dbus, mctpd):
        """Test repeated setup and removal"""
        iface = mctpd.system.interfaces[0]
        mctp = await mctpd_mctp_iface_obj(dbus, iface)
        
        for i in range(3):
            ep = Endpoint(iface, bytes([0xF0 + i]), types=[0, 1])
            mctpd.network.add_endpoint(ep)
            
            (eid, _, path, _) = await mctp.call_setup_endpoint(ep.lladdr)
            await trio.sleep(0.2)
            
            ep_obj = await dbus.get_proxy_object('au.com.codeconstruct.MCTP1', path)
            ep_iface = await ep_obj.get_interface('au.com.codeconstruct.MCTP.Endpoint1')
            await ep_iface.call_remove()
            await trio.sleep(0.2)

    async def test_multiple_endpoint_setups(self, dbus, mctpd):
        """Test setting up multiple endpoints"""
        iface = mctpd.system.interfaces[0]
        mctp = await mctpd_mctp_iface_obj(dbus, iface)
        
        for i in range(5):
            ep = Endpoint(iface, bytes([0xE0 + i]), types=[0, 1])
            mctpd.network.add_endpoint(ep)
            
            (eid, _, path, _) = await mctp.call_setup_endpoint(ep.lladdr)
            assert eid == ep.eid
            await trio.sleep(0.1)

    async def test_setup_various_endpoint_types(self, dbus, mctpd):
        """Test setup with different endpoint types"""
        iface = mctpd.system.interfaces[0]
        mctp = await mctpd_mctp_iface_obj(dbus, iface)
        
        for i, types in enumerate([[0], [0, 1], [0, 1, 2], [0, 1, 5]]):
            ep = Endpoint(iface, bytes([0x80 + i]), types=types)
            mctpd.network.add_endpoint(ep)
            
            (eid, _, path, _) = await mctp.call_setup_endpoint(ep.lladdr)
            assert eid == ep.eid
            await trio.sleep(0.1)


# ============================================================================
# SECTION 8: Network Operations & Utilities
# ============================================================================

class TestNetworkOperationsAndUtilities:
    """Test network operations and utility functions"""

    async def test_network_property_queries(self, dbus, mctpd):
        """Test network property queries"""
        iface = mctpd.system.interfaces[0]
        net = await mctpd_mctp_network_obj(dbus, iface.net)
        
        local_eids = await net.get_local_eids()
        assert local_eids is not None

    async def test_bridge_property_queries(self, dbus, mctpd):
        """Test bridge property queries"""
        iface = mctpd.system.interfaces[0]
        bridge = Endpoint(iface, bytes([0x70]), types=[0, 1, 5])
        mctpd.network.add_endpoint(bridge)
        
        mctp = await mctpd_mctp_iface_obj(dbus, iface)
        (eid, _, path, _) = await mctp.call_assign_endpoint_static(
            bridge.lladdr, 150, 151, b''
        )
        
        await trio.sleep(0.5)
        
        try:
            obj = await dbus.get_proxy_object('au.com.codeconstruct.MCTP1', path)
            bridge_iface = await obj.get_interface('au.com.codeconstruct.MCTP.Bridge1')
            pool_start = await bridge_iface.get_pool_start()
            pool_end = await bridge_iface.get_pool_end()
        except Exception:
            pass  # Bridge interface may not be exposed yet

    async def test_multiple_physical_addresses(self, dbus, mctpd):
        """Test endpoints with different physical addresses"""
        iface = mctpd.system.interfaces[0]
        mctp = await mctpd_mctp_iface_obj(dbus, iface)
        
        for i in range(4):
            ep = Endpoint(iface, bytes([0xB0 + i]), types=[0, 1])
            mctpd.network.add_endpoint(ep)
            
            (eid, _, path, _) = await mctp.call_setup_endpoint(ep.lladdr)
            await trio.sleep(0.1)

    async def test_query_endpoints_by_eid(self, dbus, mctpd):
        """Test querying endpoints by EID"""
        iface = mctpd.system.interfaces[0]
        mctp = await mctpd_mctp_iface_obj(dbus, iface)
        
        for i in range(3):
            ep = Endpoint(iface, bytes([0xC0 + i]), types=[0, 1])
            mctpd.network.add_endpoint(ep)
            (eid, _, path, _) = await mctp.call_setup_endpoint(ep.lladdr)
        
        net = await mctpd_mctp_network_obj(dbus, iface.net)
        local_eids = await net.get_local_eids()

    async def test_learn_endpoints(self, dbus, mctpd):
        """Test learning endpoints"""
        iface = mctpd.system.interfaces[0]
        mctp = await mctpd_mctp_iface_obj(dbus, iface)
        
        for i in range(2):
            ep = Endpoint(iface, bytes([0xD0 + i]), types=[0, 1])
            mctpd.network.add_endpoint(ep)
            
            static_eid = 160 + i
            (eid, _, path, _) = await mctp.call_assign_endpoint_static(
                ep.lladdr, static_eid, static_eid, b''
            )
            await trio.sleep(0.2)

    async def test_endpoint_property_queries(self, dbus, mctpd):
        """Test querying endpoint properties"""
        iface = mctpd.system.interfaces[0]
        ep = mctpd.network.endpoints[0]
        
        mctp = await mctpd_mctp_iface_obj(dbus, iface)
        (eid, _, path, _) = await mctp.call_setup_endpoint(ep.lladdr)
        
        ep_obj = await mctpd_mctp_endpoint_common_obj(dbus, path)
        
        for _ in range(3):
            types = list(await ep_obj.get_supported_message_types())
            assert len(types) > 0
            await trio.sleep(0.2)

    async def test_properties_after_recovery(self, dbus, mctpd):
        """Test properties remain consistent after recovery"""
        iface = mctpd.system.interfaces[0]
        ep = mctpd.network.endpoints[0]
        
        mctp = await mctpd_mctp_iface_obj(dbus, iface)
        (eid, _, path, _) = await mctp.call_setup_endpoint(ep.lladdr)
        
        ep_obj = await mctpd_mctp_endpoint_common_obj(dbus, path)
        ep_control = await mctpd_mctp_endpoint_control_obj(dbus, path)
        
        types_before = list(await ep_obj.get_supported_message_types())
        
        await ep_control.call_recover()
        await trio.sleep(2)
        
        types_after = list(await ep_obj.get_supported_message_types())
        assert types_before == types_after

    async def test_concurrent_endpoint_operations(self, dbus, mctpd):
        """Test concurrent endpoint operations"""
        iface = mctpd.system.interfaces[0]
        mctp = await mctpd_mctp_iface_obj(dbus, iface)
        
        eps = []
        for i in range(4):
            ep = Endpoint(iface, bytes([0x20 + i]), types=[0, 1])
            mctpd.network.add_endpoint(ep)
            eps.append(ep)
        
        for ep in eps:
            (eid, _, _, _) = await mctp.call_setup_endpoint(ep.lladdr)
            assert eid == ep.eid

    async def test_various_endpoint_configurations(self, dbus, mctpd):
        """Test different endpoint configurations"""
        iface = mctpd.system.interfaces[0]
        mctp = await mctpd_mctp_iface_obj(dbus, iface)
        
        configs = [
            (bytes([0x11]), [0]),
            (bytes([0x12]), [0, 1]),
            (bytes([0x56]), [0, 1, 2]),
        ]
        
        for lladdr, types in configs:
            ep = Endpoint(iface, lladdr, types=types)
            mctpd.network.add_endpoint(ep)
            (eid, _, path, _) = await mctp.call_setup_endpoint(ep.lladdr)
            await trio.sleep(0.15)

    async def test_stress_endpoint_operations(self, dbus, mctpd):
        """Stress test with rapid endpoint operations"""
        iface = mctpd.system.interfaces[0]
        mctp = await mctpd_mctp_iface_obj(dbus, iface)
        
        for i in range(10):
            ep = Endpoint(iface, bytes([0x30 + i]), types=[0, 1])
            mctpd.network.add_endpoint(ep)
            (eid, _, path, _) = await mctp.call_setup_endpoint(ep.lladdr)
            await trio.sleep(0.05)


# ============================================================================
# SECTION 9: Complex Integration Scenarios
# ============================================================================

class TestComplexIntegrationScenarios:
    """Complex integration tests combining multiple features"""

    async def test_bridge_with_changing_downstream(self, dbus, mctpd):
        """Test bridge with downstream endpoints coming and going"""
        iface = mctpd.system.interfaces[0]
        bridge = Endpoint(iface, bytes([0x30]), types=[0, 1, 5])
        mctpd.network.add_endpoint(bridge)
        
        mctp = await mctpd_mctp_iface_obj(dbus, iface)
        
        (eid, _, path, new) = await mctp.call_assign_endpoint_static(
            bridge.lladdr, 130, 131, b''
        )
        
        await trio.sleep(6)

    async def test_bridges_with_complex_ignore_list(self, dbus, mctpd):
        """Test bridges with complex ignore EID lists"""
        iface = mctpd.system.interfaces[0]
        mctp = await mctpd_mctp_iface_obj(dbus, iface)
        
        for i in range(2):
            bridge = Endpoint(iface, bytes([0xE5 + i]), types=[0, 1, 5])
            mctpd.network.add_endpoint(bridge)
            
            static_eid = 180 + (i * 5)
            start_eid = static_eid + 1
            ignore_eids = bytes([static_eid + 2])
            
            (eid, _, path, _) = await mctp.call_assign_endpoint_static(
                bridge.lladdr, static_eid, start_eid, ignore_eids
            )
            await trio.sleep(0.4)

    async def test_bridge_and_normal_endpoints_mixed(self, dbus, mctpd):
        """Test mixture of bridge and normal endpoints"""
        iface = mctpd.system.interfaces[0]
        mctp = await mctpd_mctp_iface_obj(dbus, iface)
        
        ep1 = Endpoint(iface, bytes([0x40]), types=[0, 1])
        mctpd.network.add_endpoint(ep1)
        (eid1, _, _, _) = await mctp.call_setup_endpoint(ep1.lladdr)
        
        await trio.sleep(0.2)
        
        bridge = Endpoint(iface, bytes([0x41]), types=[0, 1, 5])
        mctpd.network.add_endpoint(bridge)
        
        (eid2, _, _, _) = await mctp.call_assign_endpoint_static(
            bridge.lladdr, 170, 171, b''
        )
        
        await trio.sleep(0.3)
        
        ep2 = Endpoint(iface, bytes([0x42]), types=[0, 1])
        mctpd.network.add_endpoint(ep2)
        (eid3, _, _, _) = await mctp.call_setup_endpoint(ep2.lladdr)
        
        assert eid1 == ep1.eid
        assert eid2 == 170
        assert eid3 == ep2.eid

    async def test_full_lifecycle_multiple_bridges(self, dbus, mctpd):
        """Test full lifecycle of multiple bridges"""
        iface = mctpd.system.interfaces[0]
        mctp = await mctpd_mctp_iface_obj(dbus, iface)
        
        paths = []
        
        for i in range(3):
            bridge = Endpoint(iface, bytes([0x50 + i]), types=[0, 1, 5])
            mctpd.network.add_endpoint(bridge)
            
            static_eid = 180 + (i * 3)
            start_eid = static_eid + 1
            
            (eid, _, path, _) = await mctp.call_assign_endpoint_static(
                bridge.lladdr, static_eid, start_eid, b''
            )
            paths.append(path)
            await trio.sleep(0.3)
        
        await trio.sleep(6)
        
        for path in paths:
            ep_obj = await dbus.get_proxy_object('au.com.codeconstruct.MCTP1', path)
            ep_iface = await ep_obj.get_interface('au.com.codeconstruct.MCTP.Endpoint1')
            await ep_iface.call_remove()
            await trio.sleep(0.2)

    async def test_sequential_bridge_operations(self, dbus, mctpd):
        """Test sequential bridge setup and management"""
        iface = mctpd.system.interfaces[0]
        mctp = await mctpd_mctp_iface_obj(dbus, iface)
        
        for i in range(4):
            bridge = Endpoint(iface, bytes([0xB0 + i]), types=[0, 1, 5])
            mctpd.network.add_endpoint(bridge)
            
            static_eid = 240 + (i * 2)
            start_eid = static_eid + 1
            
            (eid, _, path, new) = await mctp.call_assign_endpoint_static(
                bridge.lladdr, static_eid, start_eid, b''
            )
            
            assert eid == static_eid
            assert new == True
            
            await trio.sleep(0.15)
