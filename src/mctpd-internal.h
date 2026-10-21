/*
 * SPDX-FileCopyrightText: Copyright (c)  NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <systemd/sd-event.h>
#include <systemd/sd-bus.h>

#include "mctp.h"
#include "mctp-util.h"
#include "mctp-netlink.h"
#include "mctp-control-spec.h"
#include "mctp-ops.h"
#include "mctpd-util.h"
#include "mctp-log.h"

#define max(a, b) ((a) > (b) ? (a) : (b))
#define min(a, b) ((a) < (b) ? (a) : (b))

#define MCTP_DBUS_PATH "/au/com/codeconstruct/mctp1"
#define MCTP_DBUS_PATH_NETWORKS "/au/com/codeconstruct/mctp1/networks"
#define MCTP_DBUS_PATH_LINKS "/au/com/codeconstruct/mctp1/interfaces"
#define CC_MCTP_DBUS_IFACE_BUSOWNER "au.com.codeconstruct.MCTP.BusOwner1"
#define CC_MCTP_DBUS_IFACE_ENDPOINT "au.com.codeconstruct.MCTP.Endpoint1"
#define CC_MCTP_DBUS_IFACE_BRIDGE "au.com.codeconstruct.MCTP.Bridge1"
#define CC_MCTP_DBUS_IFACE_TESTING "au.com.codeconstruct.MCTPTesting"
#define MCTP_DBUS_NAME "au.com.codeconstruct.MCTP1"
#define MCTP_DBUS_IFACE_ENDPOINT "xyz.openbmc_project.MCTP.Endpoint"
#define OPENBMC_IFACE_COMMON_UUID "xyz.openbmc_project.Common.UUID"
#define MCTP_DBUS_IFACE_BINDING "xyz.openbmc_project.MCTP.Binding"
#define CC_MCTP_DBUS_IFACE_INTERFACE "au.com.codeconstruct.MCTP.Interface1"
#define CC_MCTP_DBUS_NETWORK_INTERFACE "au.com.codeconstruct.MCTP.Network1"
#define OPENBMC_SERVICE_READINESS_IFACE "xyz.openbmc_project.State.ServiceReady"

#define BRIDGE_SETTLE_DELAY_SEC 4

// Service readiness state constants
#define SERVICE_STATE_STARTING_STR \
	"xyz.openbmc_project.State.ServiceReady.States.Starting"
#define SERVICE_STATE_ENABLED_STR \
	"xyz.openbmc_project.State.ServiceReady.States.Enabled"
#define SERVICE_TYPE_MCTP_STR \
	"xyz.openbmc_project.State.ServiceReady.ServiceTypes.MCTP"
// an arbitrary constant for use with sd_id128_get_machine_app_specific()

static const uint64_t max_poll_interval_ms = 10000;
static const uint64_t min_poll_interval_ms = 2500;
static const mctp_eid_t eid_alloc_min = 0x08;
static const mctp_eid_t eid_alloc_max = 0xfe;
static const size_t static_pool_eid_count = (size_t)UINT8_MAX + 1;
static const uint8_t MCTP_TYPE_VENDOR_PCIE = 0x7e;
static const uint8_t MCTP_TYPE_VENDOR_IANA = 0x7f;

struct dest_phys {
	int ifindex;
	uint8_t hwaddr[MAX_ADDR_LEN];
	size_t hwaddr_len;
};
typedef struct dest_phys dest_phys;

/* Table of per-network details */
struct net {
	struct ctx *ctx;
	uint32_t net;

	// EID mappings, NULL is unused.
	struct peer *peers[256];

	sd_bus_slot *slot;
	char *path;
};

struct ctx;

// all local peers have the same phys
static const dest_phys local_phys = { .ifindex = 0 };

enum endpoint_role {
	ENDPOINT_ROLE_UNKNOWN,
	ENDPOINT_ROLE_BUS_OWNER,
	ENDPOINT_ROLE_ENDPOINT,
};

struct role {
	enum endpoint_role role;
	const char *conf_val;
	const char *dbus_val;
};

// Endpoint poll context for bridged endpoint polling
struct ep_poll_ctx {
	struct peer *bridge;
	mctp_eid_t poll_eid;
};

static const struct role roles[] = {
	[ENDPOINT_ROLE_UNKNOWN] = {
		.role = ENDPOINT_ROLE_UNKNOWN,
		.conf_val = "unknown",
		.dbus_val = "Unknown",
	},
	[ENDPOINT_ROLE_BUS_OWNER] = {
		.role = ENDPOINT_ROLE_BUS_OWNER,
		.conf_val = "bus-owner",
		.dbus_val = "BusOwner",
	},
	[ENDPOINT_ROLE_ENDPOINT] = {
		.role = ENDPOINT_ROLE_ENDPOINT,
		.conf_val = "endpoint",
		.dbus_val = "Endpoint",
	},
};

enum discovery_state {
	DISCOVERY_UNSUPPORTED,
	DISCOVERY_DISCOVERED,
	DISCOVERY_UNDISCOVERED,
};

struct link {
	enum discovery_state discovered;
	bool published;
	int ifindex;
	enum endpoint_role role;
	uint8_t phys_binding;
	char *sysfs_path;

	char *path;
	sd_bus_slot *slot_iface;
	sd_bus_slot *slot_busowner;
	sd_bus_slot *slot_service_readiness;
	sd_event_source *role_defer;

	struct ctx *ctx;

	// Service readiness state
	enum {
		SERVICE_STATE_STARTING,
		SERVICE_STATE_ENABLED,
	} service_state;
};

struct vdm_type_support;

struct peer {
	uint32_t net;
	mctp_eid_t eid;

	// multiple local interfaces can have the same eid,
	// so we store a refcount to use when removing peers.
	int local_count;

	// Only set for .state == REMOTE
	dest_phys phys;

	enum {
		REMOTE,
		// Local address. Note that multiple interfaces
		// in a network may have the same local address.
		LOCAL,
	} state;

	// visible to dbus, set by publish/unpublish_peer()
	bool published;
	sd_bus_slot *slot_obmc_endpoint;
	sd_bus_slot *slot_cc_endpoint;
	sd_bus_slot *slot_bridge;
	sd_bus_slot *slot_uuid;
	sd_bus_slot *slot_binding_endpoint;
	char *path;

	bool have_neigh;
	bool have_route;
	// This will be set to true for any direct endpoint (except bridged endpoints)
	bool is_direct_endpoint;

	// MTU for the route. Set to the interface's minimum MTU initially,
	// or changed by .SetMTU method
	uint32_t mtu;

	// malloc()ed list of supported message types, from Get Message Type
	uint8_t *message_types;
	size_t num_message_types;

	struct vdm_type_support *vdm_types;
	size_t num_vdm_types;

	// From Get Endpoint ID
	uint8_t endpoint_type;
	uint8_t medium_spec;

	// From Get Endpoint UUID. A malloced 16 bytes */
	uint8_t *uuid;

	// Stuff the ctx pointer into peer for tidier parameter passing
	struct ctx *ctx;

	// Connectivity state
	bool degraded;
	// Set after one ping failure; subsequent ping retries can suppress noise.
	bool ping_failed_once;

	// Local EID
	mctp_eid_t local_eid;

	mctp_eid_t pool_owner_eid;
	mctp_eid_t *ignore_eids;
	size_t num_ignore_eids;
	mctp_eid_t *static_pool_eids;
	uint8_t *ignore_message_types;
	size_t num_ignore_message_types;
	// Routing Table Data
	struct get_routing_table_entry *routing_table_entry;
	// Timer for bridge EID population
	sd_event_source *bridge_settle_timer;
	struct {
		uint64_t delay;
		sd_event_source *source;
		int npolls;
		mctp_eid_t eid;
		uint8_t endpoint_type;
		uint8_t medium_spec;
	} recovery;

	// Pool size
	uint8_t pool_size;
	uint8_t pool_start;

	struct {
		sd_event_source **sources;
	} bridge_ep_poll;
};

struct msg_type_support {
	uint8_t msg_type;
	uint32_t *versions;
	size_t num_versions;
	sd_bus_track *source_peer;
};

enum vid_format {
	VID_FORMAT_PCIE = MCTP_GET_VDM_SUPPORT_PCIE_FORMAT_ID,
	VID_FORMAT_IANA = MCTP_GET_VDM_SUPPORT_IANA_FORMAT_ID,
};

struct vdm_type_support {
	enum vid_format format;
	union {
		uint16_t pcie;
		uint32_t iana;
	} vendor_id;
	uint16_t cmd_set;
	sd_bus_track *source_peer;
};

struct interface_config {
	struct interface_config_match {
		enum {
			IFACE_MATCH_ALL,
			IFACE_MATCH_BINDING,
			IFACE_MATCH_PATH,
		} type;
		union {
			enum mctp_phys_binding binding;
			char *path;
		};
	} match;

	bool role_set;
	enum endpoint_role role;
};

struct ctx {
	sd_event *event;
	sd_bus *bus;

	// Configuration
	char *config_filename;

	mctp_nl *nl;

	// Default BMC role in All of MCTP medium interface
	enum endpoint_role default_role;

	// An allocated array of peers, changes address (reallocated) during runtime
	struct peer **peers;
	size_t num_peers;

	struct net **nets;
	size_t num_nets;

	// the range we allocate any dynamic EIDs from
	mctp_eid_t dyn_eid_min;
	mctp_eid_t dyn_eid_max;

	// Timeout in usecs for a MCTP response
	uint64_t mctp_timeout;

	// Next IID to use
	uint8_t iid;

	uint8_t uuid[16];

	// Supported message types and their versions
	struct msg_type_support *supported_msg_types;
	size_t num_supported_msg_types;

	struct vdm_type_support *supported_vdm_types;
	size_t num_supported_vdm_types;

	// Verbose logging
	bool verbose;

	//  maximum pool size for assumed MCTP Bridge
	uint8_t max_pool_size;

	// Own Bridge EID
	mctp_eid_t bmc_bridge_eid;
	mctp_eid_t *bmc_ignore_eids;
	uint8_t bmc_ignore_eids_count;
	// Cached Routing Entires
	struct {
		struct routing_info_entry **routing_info_entries;
		size_t *entry_sizes;
		uint8_t count;
	} cache_entries;
	// bus owner/bridge polling interval in usecs for
	// checking endpoint's accessibility.
	uint64_t endpoint_poll;

	// interface configuration (from config file), to be matched and
	// applied on new interface events
	struct interface_config *interface_configs;
	size_t num_interface_configs;

	// Head of the per-physaddr in-flight ops index. Used by the four
	// endpoint-lifecycle D-Bus method handlers (SetupEndpoint,
	// AssignEndpoint, AssignEndpointStatic, LearnEndpoint) to reject
	// concurrent calls against the same physaddr with
	// org.freedesktop.DBus.Error.LimitsExceeded. mctpd is single-threaded
	// (sd-event main loop) so this list needs no lock.
	struct in_flight_node *in_flight_ops;
};

/* Stage at which a control command exchange failed, recorded by
 * endpoint_query_addr() (sync) or the async step engine so that callers
 * can describe the failure. */
enum mctp_ctrl_cmd_fail_stage {
	/* no failure, or a response was received: see the validation
	 * result and the response completion code instead */
	MCTP_CTRL_CMD_FAIL_NONE = 0,
	/* the request could not be sent */
	MCTP_CTRL_CMD_FAIL_SEND,
	/* no response was received before the timeout, on any attempt */
	MCTP_CTRL_CMD_FAIL_TIMEOUT,
	/* a response or transport error arrived but could not be read */
	MCTP_CTRL_CMD_FAIL_RECV,
};

/* data for a command + response.
 *
 * req is populated by the caller. resp is allocated during command submission,
 * and must be freed by the caller.
 */
struct mctp_ctrl_cmd {
	/* populated by caller */
	void *req;
	size_t req_len;
	bool disable_retry;
	/* suppress repetitive per-transaction logs (e.g. failed ping) */
	bool suppress_logs;
	/* command is part of endpoint discovery: failures are reported
	 * through DiscoveryCommandFailed instead of TransportError */
	bool discovery;

	/* populated on failure by endpoint_query_addr() */
	enum mctp_ctrl_cmd_fail_stage fail_stage;

	/* populated on response RX */
	void *resp;
	size_t resp_len;
	struct sockaddr_mctp_ext resp_addr;
};

#define mctp_ctrl_cmd_init_from_req_type(cmd, req) \
	do {                                       \
		(cmd)->req = &req;                 \
		(cmd)->req_len = sizeof(req);      \
	} while (0)

/* frees response data, but not cmd itself, as this will typically be on the
 * stack
 */
static inline void mctp_ctrl_cmd_free(struct mctp_ctrl_cmd *cmd)
{
	free(cmd->resp);
	cmd->resp = NULL;
}

struct in_flight_node;
struct pending_op;

enum op_kind {
	OP_SETUP_ENDPOINT,
	OP_ASSIGN_ENDPOINT,
	OP_ASSIGN_ENDPOINT_STATIC,
	OP_LEARN_ENDPOINT,
	OP_NET_LEARN_ENDPOINT,
	OP_GET_ROUTING_TABLE,
	OP_RECOVER, /* synthetic op: async peer_endpoint_recover (call == NULL) */
	OP_ROUTING_INFO_UPDATE, /* synthetic fire-and-forget RIU to a bridge */
};

enum op_step {
	STEP_NONE = 0,
	STEP_GET_ENDPOINT_ID,
	STEP_SET_ENDPOINT_ID,
	STEP_GET_ROUTING_TABLE_ENTRIES, /* reused — now chained across fragments */
	STEP_QPP_MSGTYPES, /* query_peer_properties msgtypes */
	STEP_QPP_VDM, /* query_peer_properties vendor-defined msg types */
	STEP_QPP_UUID, /* query_peer_properties uuid */
	STEP_QPP_ENDPOINT_ID, /* query_peer_properties eid confirm */
	STEP_QPP_ROUTING_DATA, /* bridge-pool routing data */
	STEP_ALLOCATE_ENDPOINT_IDS, /* bridge pool allocation */
	STEP_POOL_FINALIZE, /* per-EID async pool finalize */
	STEP_RECOVER_GET_EID, /* recovery probe: Get Endpoint ID */
	STEP_RECOVER_UUID, /* recovery: Get Endpoint UUID (by phys or by EID) */
	STEP_RECOVER_SET_EID, /* recovery branch B: Set Endpoint ID re-assign */
	STEP_RECOVER_ASSIGN_SET_EID, /* recovery branch A: fresh-assign Set EID */
	STEP_ROUTING_INFO_UPDATE, /* fire-and-forget RIU to a bridge */
	STEP_DONE,
};

typedef void (*op_step_cb_t)(struct pending_op *op, int rc, uint8_t *resp,
			     size_t resp_len,
			     const struct sockaddr_mctp_ext *resp_addr);

struct in_flight_node {
	uint32_t net_id;
	uint8_t hwaddr[MAX_ADDR_LEN];
	uint8_t hwaddr_len;
	int ifindex; /* part of key for Interface1-scope calls */
	struct pending_op *op;
	struct in_flight_node *next; /* simple singly-linked list — small N */
};

struct pending_op {
	/* Held inbound D-Bus call; NULL for synthetic ops. */
	sd_bus_message *call;

	/* Fires pending_op_cleanup() (no reply) if the caller disconnects. */
	sd_bus_track *caller_track;

	/* Per-step socket and event sources; closed when the step completes. */
	int sock_fd;
	sd_event_source *io_src;
	sd_event_source *tm_src;

	/* Saved destination address for error reporting. */
	struct sockaddr_mctp_ext req_addr;

	/* Operation identity. */
	enum op_kind kind;
	struct link *link; /* set for Interface1-scope invocations */
	struct net *net; /* set for Network1-scope invocations */
	dest_phys dest; /* physaddr argument from the caller */
	struct peer *peer; /* working peer pointer (may be NULL) */
	bool is_dummy; /* peer created just for this op (Learn) */
	bool is_direct_endpoint;
	mctp_eid_t static_eid; /* AssignEndpointStatic only */

	/* AssignEndpointStatic only: caller-supplied bridge pool start
	 * and ignore lists. Owned by the call message; do not free. */
	uint8_t static_pool_start;
	const uint8_t *ignore_eids;
	size_t ignore_eids_len;
	const uint8_t *ignore_message_types;
	size_t ignore_message_types_len;

	/* State machine cursor + current step continuation. */
	enum op_step step;
	op_step_cb_t step_cb;

	/* IID of the current request; responses with another IID are
	 * rejected in cb_op_io with -ENOMSG. */
	uint8_t iid;
	uint8_t cmd_code; /* control command code of this step, for logging */

	/* query_peer_properties chain state. */
	op_step_cb_t qpp_done_cb; /* invoked when the 4-step qpp chain finishes */
	uint8_t qpp_uuid[16]; /* accumulated across STEP_QPP_UUID */
	unsigned int step_retries; /* qpp outer re-launch counter (new IID) */
	bool qpp_discovery; /* report qpp failures via DiscoveryCommandFailed */
	uint8_t qpp_vdm_selector; /* Get VDM Support set selector in flight */
	struct vdm_type_support *qpp_vdm_types; /* accumulated VDM sets */
	size_t qpp_num_vdm_types;

	/* Per-step transmit state. The request is kept so a timed-out step
	 * can be retransmitted with the same IID (DSP0237 Table 9). */
	uint8_t *step_req;
	size_t step_req_len;
	bool step_ext_addr;
	unsigned int step_attempt; /* 1-based transmission count */
	bool step_no_retry; /* probe: do not retransmit on timeout */
	bool step_discovery; /* report failures via DiscoveryCommandFailed */
	bool step_suppress; /* ping_failed_once snapshot at step start */
	enum mctp_ctrl_cmd_fail_stage step_fail_stage;

	/* GET_ROUTING_TABLE_ENTRIES fragment loop state. */
	uint8_t rt_next_handle; /* entry handle for the next fragment request */
	unsigned int rt_iter; /* fragment-loop iteration count (cap 256) */
	struct peer
		*rt_pool_peer; /* pool-owner peer the routing query runs for */
	bool *rt_active_pool_eid; /* per-pool-EID activity, freed in cleanup */
	struct get_routing_table_entry *
		*rt_local_routing; /* per-pool-EID entry */
	bool rt_is_static_pool_bridge; /* static-pool bridge fixup flag */
	op_step_cb_t rt_done_cb; /* continuation after the fragment loop */

	/* STEP_POOL_FINALIZE state; separate from rt_* since
	 * STEP_QPP_ROUTING_DATA reuses those during the loop. */
	struct peer *finalize_bridge; /* pool-owner bridge peer */
	int finalize_net;
	dest_phys finalize_dest; /* physaddr for add_peer of new pool EIDs */
	bool finalize_static_pool; /* is_static_pool_bridge snapshot */
	bool *finalize_active; /* active_pool_eid[] — freed in complete/cleanup */
	struct get_routing_table_entry **finalize_routing; /* local_routing[] */
	struct link *finalize_link; /* bridge link for service-state emit */
	uint8_t finalize_pool_size; /* snapshot (bridge pool_size may change) */
	uint8_t finalize_pool_start; /* snapshot */
	uint8_t finalize_idx; /* current pool index in the per-EID loop */
	bool finalize_cur_new; /* current EID peer was freshly add_peer'd */
	struct peer *finalize_saved_peer; /* op->peer saved around the loop */
	op_step_cb_t finalize_done_cb; /* rt_done_cb, invoked when pool done */

	/* Deferred send state (sendto returned EAGAIN); finished by
	 * cb_op_send. send_buf != NULL means a send is in progress. */
	uint8_t *send_buf; /* copy of the request (caller owns the original) */
	size_t send_len;
	size_t send_off; /* bytes accepted so far (partial-send handling) */
	struct sockaddr_mctp_ext send_addr;
	bool send_ext_addr;

	/* In-flight index linkage (per-physaddr rejection). */
	struct in_flight_node *in_flight_node;

	struct ctx *ctx;
};

/* ---- shared function declarations (mctpd.c <-> mctpd-async.c) ---- */
int pending_op_begin(struct ctx *ctx, sd_bus_message *call, sd_bus_error *berr,
		     enum op_kind kind, struct link *link, struct net *net,
		     const dest_phys *dest, uint32_t net_id,
		     struct pending_op **ret_op);
int pending_op_launch_step_phys(struct pending_op *op, enum op_step step,
				const void *req, size_t req_len,
				op_step_cb_t step_cb);
void pending_op_cleanup(struct pending_op *op);
void op_after_get_endpoint_id_probe(struct pending_op *op, int rc,
				    uint8_t *resp, size_t resp_len,
				    const struct sockaddr_mctp_ext *resp_addr);
void op_after_set_endpoint_id(struct pending_op *op, int rc, uint8_t *resp,
			      size_t resp_len,
			      const struct sockaddr_mctp_ext *resp_addr);
void op_after_net_learn_endpoint_get_eid(
	struct pending_op *op, int rc, uint8_t *resp, size_t resp_len,
	const struct sockaddr_mctp_ext *resp_addr);
void op_after_get_routing_table_first(struct pending_op *op, int rc,
				      uint8_t *resp, size_t resp_len,
				      const struct sockaddr_mctp_ext *resp_addr);

/* Async step launch and query_peer_properties chain helpers. */
int pending_op_launch_step_eid(struct pending_op *op, mctp_eid_t eid,
			       uint32_t net, enum op_step step, const void *req,
			       size_t req_len, op_step_cb_t step_cb);
void qpp_start(struct pending_op *op, op_step_cb_t qpp_done_cb, bool discovery);
void pending_op_set_step_policy(struct pending_op *op, bool discovery,
				bool no_retry);
int qpp_launch_vdm(struct pending_op *op);
void op_after_qpp_vdm(struct pending_op *op, int rc, uint8_t *resp,
		      size_t resp_len, const struct sockaddr_mctp_ext *resp_addr);
const char *ext_addr_tostr(const struct sockaddr_mctp_ext *addr);
void net_learn_after_qpp_done(struct pending_op *op, int rc, uint8_t *resp,
			      size_t resp_len,
			      const struct sockaddr_mctp_ext *resp_addr);
/* Dispatch-path async query_peer_properties. Does the
 * pre-query (mtu + conditional route-add) work of setup_added_peer, then
 * launches the async qpp chain with the flow-specific done_cb. */
void dispatch_setup_added_peer_async(struct pending_op *op, struct peer *peer,
				     op_step_cb_t done_cb);
bool dispatch_qpp_failed(struct pending_op *op, int rc);
void assign_after_qpp_done(struct pending_op *op, int rc, uint8_t *resp,
			   size_t resp_len,
			   const struct sockaddr_mctp_ext *resp_addr);
void learn_after_qpp_done(struct pending_op *op, int rc, uint8_t *resp,
			  size_t resp_len,
			  const struct sockaddr_mctp_ext *resp_addr);
void setup_simple_after_qpp_done(struct pending_op *op, int rc, uint8_t *resp,
				 size_t resp_len,
				 const struct sockaddr_mctp_ext *resp_addr);
void setup_after_qpp_done(struct pending_op *op, int rc, uint8_t *resp,
			  size_t resp_len,
			  const struct sockaddr_mctp_ext *resp_addr);
void setup_after_allocate_done(struct pending_op *op, int rc, uint8_t *resp,
			       size_t resp_len,
			       const struct sockaddr_mctp_ext *resp_addr);
void assign_after_allocate_done(struct pending_op *op, int rc, uint8_t *resp,
				size_t resp_len,
				const struct sockaddr_mctp_ext *resp_addr);
void assign_after_routing_done(struct pending_op *op, int rc, uint8_t *resp,
			       size_t resp_len,
			       const struct sockaddr_mctp_ext *resp_addr);
void get_routing_table_done(struct pending_op *op, int rc, uint8_t *resp,
			    size_t resp_len,
			    const struct sockaddr_mctp_ext *resp_addr);
void op_after_qpp_msgtypes(struct pending_op *op, int rc, uint8_t *resp,
			   size_t resp_len,
			   const struct sockaddr_mctp_ext *resp_addr);
void op_after_qpp_uuid(struct pending_op *op, int rc, uint8_t *resp,
		       size_t resp_len,
		       const struct sockaddr_mctp_ext *resp_addr);
void op_after_qpp_endpoint_id(struct pending_op *op, int rc, uint8_t *resp,
			      size_t resp_len,
			      const struct sockaddr_mctp_ext *resp_addr);
void op_after_qpp_routing_data(struct pending_op *op, int rc, uint8_t *resp,
			       size_t resp_len,
			       const struct sockaddr_mctp_ext *resp_addr);
int qpp_launch_msgtypes(struct pending_op *op);
int qpp_launch_uuid(struct pending_op *op);
int qpp_launch_endpoint_id(struct pending_op *op);
int qpp_launch_routing_data(struct pending_op *op);
void allocate_eids_start(struct pending_op *op, op_step_cb_t on_done);
void op_after_allocate_eids(struct pending_op *op, int rc, uint8_t *resp,
			    size_t resp_len,
			    const struct sockaddr_mctp_ext *resp_addr);
void routing_table_loop_start(struct pending_op *op, struct peer *peer,
			      op_step_cb_t on_done);
int routing_table_launch_fragment(struct pending_op *op);
void op_after_get_routing_table_entry(struct pending_op *op, int rc,
				      uint8_t *resp, size_t resp_len,
				      const struct sockaddr_mctp_ext *resp_addr);
void rt_process_fragment(struct peer *peer,
			 struct mctp_ctrl_resp_get_routing_table *resp,
			 bool *active_pool_eid,
			 struct get_routing_table_entry **local_routing);
/* Async twin of rt_finalize_pool. */
void rt_finalize_pool_async(struct pending_op *op, struct peer *peer, int net,
			    const dest_phys *dest, bool is_static_pool_bridge,
			    bool *active_pool_eid,
			    struct get_routing_table_entry **local_routing,
			    struct link *link, op_step_cb_t done_cb);
void rt_finalize_process_next(struct pending_op *op);
void rt_finalize_pool_complete(struct pending_op *op);
void finalize_after_qpp_done(struct pending_op *op, int rc, uint8_t *resp,
			     size_t resp_len,
			     const struct sockaddr_mctp_ext *resp_addr);
int peer_set_uuid(struct peer *peer, const uint8_t uuid[16]);
bool is_eid_in_bridge_pool(const struct net *n, const struct ctx *ctx,
			   mctp_eid_t eid, struct peer **pool_owner_peer);
mctp_eid_t get_pool_start(struct peer *peer, mctp_eid_t pool_start,
			  uint8_t pool_size);
int bridge_poll_start(struct peer *peer);
int cb_populate_pool_eids(sd_event_source *s, uint64_t t, void *data);
extern const sd_bus_vtable bus_endpoint_bridge[];
void populate_pool_done(struct pending_op *op, int rc, uint8_t *resp,
			size_t resp_len,
			const struct sockaddr_mctp_ext *resp_addr);
void recover_after_get_eid(struct pending_op *op, int rc, uint8_t *resp,
			   size_t resp_len,
			   const struct sockaddr_mctp_ext *resp_addr);
int add_peer(struct ctx *ctx, const dest_phys *dest, mctp_eid_t eid,
	     uint32_t net, struct peer **ret_peer, bool allow_bridged);
void add_peer_route(struct peer *peer);
int add_pool_gw_routes_ignore_aware(struct peer *peer);
void bridge_send_cached_routing_updates(struct peer *peer);
int change_peer_eid(struct peer *peer, mctp_eid_t new_eid);
const char *command_str(uint8_t cmd);
int del_pool_gw_routes_ignore_aware(struct peer *peer);
const char *dest_phys_tostr(const dest_phys *dest);
int endpoint_assign_prepare_peer(struct ctx *ctx, sd_bus_error *berr,
				 const dest_phys *dest, mctp_eid_t static_eid,
				 bool assign_bridge, struct peer **ret_peer);
int endpoint_send_routing_info_update(struct peer *peer, mctp_eid_t first_eid,
				      uint8_t range, uint8_t entry_type,
				      uint8_t phy_addr_size, uint8_t *phy_addr);
struct peer *find_peer_by_addr(struct ctx *ctx, mctp_eid_t eid, uint32_t net);
struct peer *find_peer_by_phys(struct ctx *ctx, const dest_phys *dest);
struct in_flight_node *in_flight_find(struct ctx *ctx, uint32_t net_id,
				      const uint8_t *hwaddr, uint8_t hwaddr_len,
				      int ifindex);
int in_flight_register(struct ctx *ctx, struct pending_op *op, uint32_t net_id,
		       int ifindex);
struct net *lookup_net(struct ctx *ctx, uint32_t net);
uint8_t mctp_next_iid(struct ctx *ctx);
const char *path_from_peer(const struct peer *peer);
const char *peer_tostr(const struct peer *peer);
void pending_op_set_peer(struct pending_op *op, struct peer *peer);
void pending_op_set_static_args(struct pending_op *op, mctp_eid_t static_eid,
				uint8_t static_pool_start,
				const uint8_t *ignore_eids,
				size_t ignore_eids_len,
				const uint8_t *ignore_message_types,
				size_t ignore_message_types_len);
void add_peer_route(struct peer *peer);
int read_mctp_error_queue(struct ctx *ctx, int fd, bool verbose,
			  const struct sockaddr_mctp_ext *req_addr,
			  const void *req, size_t req_len, bool report);
void report_discovery_command_failure(struct ctx *ctx, int ifindex,
				      uint8_t cmd_code, mctp_eid_t eid,
				      const struct mctp_ctrl_cmd *cmd, int rc,
				      const char *reason);
int mctp_ctrl_validate_response(struct mctp_ctrl_cmd *cmd, size_t exp_size,
				const char *peer, uint8_t iid, uint8_t cmd_id);
int mctp_ctrl_validate_get_routing_table_response(
	uint8_t *buf, size_t rsp_size, const char *peer, uint8_t iid,
	struct sockaddr_mctp_ext *resp_addr, bool suppress_logs);
const struct get_routing_table_entry *
routing_table_entry_next(const struct get_routing_table_entry *entry);
size_t routing_info_entry_size_from_phys(size_t phyaddr_size);
bool eid_pool_range_is_valid(mctp_eid_t pool_start, unsigned int pool_size);
int peer_alloc_static_pool_eids(struct peer *peer);
void peer_static_pool_mark_eid(struct peer *peer, mctp_eid_t eid);
bool peer_static_pool_has_eid(const struct peer *peer, mctp_eid_t eid);
const char *peer_tostr_short(const struct peer *peer);
int read_message(struct ctx *ctx, int sd, uint8_t **ret_buf,
		 size_t *ret_buf_size, struct sockaddr_mctp_ext *ret_addr,
		 bool suppress_logs);
void recover_reschedule(struct pending_op *op, int rc);
int remove_peer(struct peer *peer);
void report_transaction_error(struct ctx *ctx, int error_code,
			      uint8_t direction,
			      const struct sockaddr_mctp_ext *req_addr,
			      const void *req, size_t req_len);
void schedule_riu_to_bridges(struct ctx *ctx, mctp_eid_t first_eid,
			     uint8_t eid_range, uint8_t entry_type);
void set_berr(struct ctx *ctx, int errcode, sd_bus_error *berr);
bool should_ignore_eid(const struct peer *peer, mctp_eid_t eid);
int publish_peer(struct peer *peer, bool add_route);
__attribute__((format(printf, 1, 2))) void bug_warn(const char *fmt, ...);
