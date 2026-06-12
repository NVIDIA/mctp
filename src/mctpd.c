/* SPDX-License-Identifier: GPL-2.0 */
/*
 * mctpd: bus owner for MCTP using Linux kernel
 *
 * Copyright (c) 2021 Code Construct
 * Copyright (c) 2021 Google
 */

#define _GNU_SOURCE
#include "config.h"

#include <assert.h>
#include <systemd/sd-bus-vtable.h>
#include <time.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <err.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <signal.h>

#include <systemd/sd-event.h>
#include <systemd/sd-bus.h>
#include <systemd/sd-id128.h>

#include "toml.h"

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
static const char *mctpd_appid = "67369c05-4b97-4b7e-be72-65cfd8639f10";
static const char *conf_file_default = MCTPD_CONF_FILE_DEFAULT;

static const uint64_t max_poll_interval_ms = 10000;
static const uint64_t min_poll_interval_ms = 2500;
static const mctp_eid_t eid_alloc_min = 0x08;
static const mctp_eid_t eid_alloc_max = 0xfe;
static const uint8_t MCTP_TYPE_VENDOR_PCIE = 0x7e;
static const uint8_t MCTP_TYPE_VENDOR_IANA = 0x7f;

// arbitrary sanity
static size_t MAX_PEER_SIZE = 1000000;

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

	char *path;
	sd_bus_slot *slot_iface;
	sd_bus_slot *slot_busowner;
	sd_bus_slot *slot_service_readiness;

	struct ctx *ctx;

	// Service readiness state
	enum {
		SERVICE_STATE_STARTING,
		SERVICE_STATE_ENABLED,
	} service_state;
};

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
};

static int emit_endpoint_added(const struct peer *peer);
static int emit_endpoint_removed(const struct peer *peer);
static int emit_interface_added(struct link *link);
static int emit_interface_removed(struct link *link);
static int emit_net_added(struct ctx *ctx, struct net *net);
static int emit_net_removed(struct ctx *ctx, struct net *net);
static int add_peer(struct ctx *ctx, const dest_phys *dest, mctp_eid_t eid,
		    uint32_t net, struct peer **ret_peer, bool allow_bridged);
static int add_peer_from_addr(struct ctx *ctx,
			      const struct sockaddr_mctp_ext *addr,
			      struct peer **ret_peer);
static int remove_peer(struct peer *peer);
static int query_peer_properties(struct peer *peer);
static int setup_added_peer(struct peer *peer);
static void add_peer_route(struct peer *peer);
static int publish_peer(struct peer *peer, bool add_route);
static int unpublish_peer(struct peer *peer);
static int peer_route_update(struct peer *peer, uint16_t type);
static int peer_neigh_update(struct peer *peer, uint16_t type);
static int remove_bridged_peers(struct peer *bridge);
static int add_interface_local(struct ctx *ctx, int ifindex);
static int del_interface(struct link *link);
static int rename_interface(struct ctx *ctx, struct link *link, int ifindex);
static int change_net_interface(struct ctx *ctx, int ifindex, uint32_t old_net);
static int add_local_eid(struct ctx *ctx, uint32_t net, int eid);
static int del_local_eid(struct ctx *ctx, uint32_t net, int eid);
static int add_net(struct ctx *ctx, uint32_t net);
static void del_net(struct net *net);
static int add_interface(struct ctx *ctx, int ifindex);
static int endpoint_allocate_eids(struct peer *peer);
static int query_routing_table(struct peer *peer);
static bool should_ignore_eid(const struct peer *peer, mctp_eid_t eid);
static int add_pool_gw_routes_ignore_aware(struct peer *peer);
static int del_pool_gw_routes_ignore_aware(struct peer *peer);
static int endpoint_send_routing_info_update(struct peer *peer,
					     mctp_eid_t first_eid,
					     uint8_t range, uint8_t entry_type,
					     uint8_t phy_addr_size,
					     uint8_t *phy_addr);

static const sd_bus_vtable bus_endpoint_obmc_vtable[];
static const sd_bus_vtable bus_endpoint_cc_vtable[];
static const sd_bus_vtable bus_endpoint_bridge[];
static const sd_bus_vtable bus_endpoint_uuid_vtable[];
static const sd_bus_vtable bus_endpoint_binding_vtable[];

__attribute__((format(printf, 1, 2))) static void bug_warn(const char *fmt, ...)
{
	char *bug_fmt = NULL;
	va_list ap;
	int rc;

	rc = asprintf(&bug_fmt, "BUG: %s", fmt);
	if (rc < 0)
		return;

	va_start(ap, fmt);
	mctp_ops.bug_warn(bug_fmt, ap);
	va_end(ap);

	free(bug_fmt);
}

mctp_eid_t local_addr(const struct ctx *ctx, int ifindex)
{
	mctp_eid_t *eids, ret = 0;
	size_t num;

	eids = mctp_nl_addrs_byindex(ctx->nl, ifindex, &num);
	if (num)
		ret = eids[0];
	free(eids);
	return ret;
}

static void *dfree(void *ptr);
static int read_mctp_error_queue(struct ctx *ctx, int fd, bool verbose,
				 const struct sockaddr_mctp_ext *req_addr);

static struct net *lookup_net(struct ctx *ctx, uint32_t net)
{
	size_t i;
	for (i = 0; i < ctx->num_nets; i++)
		if (ctx->nets[i]->net == net)
			return ctx->nets[i];
	return NULL;
}

static bool match_phys(const dest_phys *d1, const dest_phys *d2)
{
	return d1->ifindex == d2->ifindex && d1->hwaddr_len == d2->hwaddr_len &&
	       (d2->hwaddr_len == 0 ||
		!memcmp(d1->hwaddr, d2->hwaddr, d1->hwaddr_len));
}

static struct peer *find_peer_by_phys(struct ctx *ctx, const dest_phys *dest)
{
	for (size_t i = 0; i < ctx->num_peers; i++) {
		struct peer *peer = ctx->peers[i];
		if (peer->state != REMOTE)
			continue;
		if (match_phys(&peer->phys, dest))
			return peer;
	}
	return NULL;
}

static struct peer *find_peer_by_addr(struct ctx *ctx, mctp_eid_t eid,
				      uint32_t net)
{
	struct net *n = lookup_net(ctx, net);

	if (eid != 0 && n && n->peers[eid])
		return n->peers[eid];
	return NULL;
}

static size_t routing_info_entry_size_from_phys(size_t phyaddr_size)
{
	return offsetof(struct routing_info_entry, phys_address) +
	       phyaddr_size;
}

static int routing_info_update_get_single_entry(
	const struct mctp_ctrl_cmd_routing_info_update *req, size_t buf_size,
	const struct routing_info_entry **entry, size_t *entry_size,
	size_t *phyaddr_size)
{
	size_t entries_offset =
		offsetof(struct mctp_ctrl_cmd_routing_info_update, entries);
	size_t min_entry_size = routing_info_entry_size_from_phys(0);

	if (buf_size < entries_offset)
		return -ENOMSG;

	if (buf_size < entries_offset + min_entry_size)
		return -ENOMSG;

	/* TODO: Only a single routing-info entry is handled today. Devices
	 * may send a Routing Info Update (RUI) carrying multiple entries; when
	 * that case appears this check must be updated to iterate over all
	 * entries instead of rejecting number_of_entries != 1. */
	if (req->number_of_entries != 1)
		return -EINVAL;

	*phyaddr_size = buf_size - entries_offset - min_entry_size;
	if (*phyaddr_size > UINT8_MAX)
		return -EMSGSIZE;

	*entry_size = routing_info_entry_size_from_phys(*phyaddr_size);
	*entry = (const struct routing_info_entry *)req->entries;
	return 0;
}

static int cache_routing_info_entry(struct ctx *ctx,
				    const struct routing_info_entry *entry,
				    size_t entry_size)
{
	struct routing_info_entry **new_entries;
	size_t *new_sizes;
	struct routing_info_entry *copy_entry;
	size_t new_count;

	if (entry_size < routing_info_entry_size_from_phys(0))
		return -EINVAL;

	if (ctx->cache_entries.count == UINT8_MAX)
		return -ENOSPC;

	copy_entry = malloc(entry_size);
	if (!copy_entry)
		return -ENOMEM;
	memcpy(copy_entry, entry, entry_size);

	new_count = (size_t)ctx->cache_entries.count + 1;
	new_entries = realloc(ctx->cache_entries.routing_info_entries,
			      new_count * sizeof(*new_entries));
	if (!new_entries) {
		free(copy_entry);
		return -ENOMEM;
	}
	ctx->cache_entries.routing_info_entries = new_entries;

	new_sizes = realloc(ctx->cache_entries.entry_sizes,
			    new_count * sizeof(*new_sizes));
	if (!new_sizes) {
		free(copy_entry);
		return -ENOMEM;
	}
	ctx->cache_entries.entry_sizes = new_sizes;

	ctx->cache_entries.routing_info_entries[ctx->cache_entries.count] =
		copy_entry;
	ctx->cache_entries.entry_sizes[ctx->cache_entries.count] = entry_size;
	ctx->cache_entries.count += 1;
	return 0;
}

static int find_local_eids_by_net(struct net *net, size_t *local_eid_cnt,
				  mctp_eid_t *ret_eids)
{
	size_t local_count = 0;
	struct peer *peer;

	*local_eid_cnt = 0;

	for (size_t t = 0; t < 256; t++) {
		peer = net->peers[t];
		if (!peer)
			continue;

		if (peer && (peer->state == LOCAL))
			ret_eids[local_count++] = t;
	}
	*local_eid_cnt = local_count;

	return 0;
}

/* Returns a deferred free pointer */
static const char *dest_phys_tostr(const dest_phys *dest)
{
	char hex[MAX_ADDR_LEN * 4];
	char *buf;
	size_t l = 50 + sizeof(hex);
	buf = malloc(l);
	if (!buf) {
		return "Out of memory";
	}
	write_hex_addr(dest->hwaddr, dest->hwaddr_len, hex, sizeof(hex));
	snprintf(buf, l, "physaddr if %d hw len %zu 0x%s", dest->ifindex,
		 dest->hwaddr_len, hex);
	return dfree(buf);
}

static const char *ext_addr_tostr(const struct sockaddr_mctp_ext *addr)
{
	char hex[MAX_ADDR_LEN * 4];
	char *buf;
	size_t l = 256;
	buf = malloc(l);
	if (!buf) {
		return "Out of memory";
	}

	write_hex_addr(addr->smctp_haddr, addr->smctp_halen, hex, sizeof(hex));
	snprintf(
		buf, l,
		"sockaddr_mctp_ext eid %d net %u type 0x%02x if %d hw len %hhu 0x%s",
		addr->smctp_base.smctp_addr.s_addr,
		addr->smctp_base.smctp_network, addr->smctp_base.smctp_type,
		addr->smctp_ifindex, addr->smctp_halen, hex);
	return dfree(buf);
}

static const char *peer_tostr(const struct peer *peer)
{
	size_t l = 300;
	char *str = NULL;

	str = malloc(l);
	if (!str) {
		return "Out of memory";
	}
	snprintf(str, l, "peer eid %d net %u phys %s state %d", peer->eid,
		 peer->net, dest_phys_tostr(&peer->phys), peer->state);
	return dfree(str);
}

static const char *peer_tostr_short(const struct peer *peer)
{
	size_t l = 30;
	char *str = NULL;

	str = malloc(l);
	if (!str) {
		return "Out of memory";
	}
	snprintf(str, l, "%u:%d", peer->net, peer->eid);
	return dfree(str);
}

static int defer_free_handler(sd_event_source *s, void *userdata)
{
	free(userdata);
	sd_event_source_unref(s);
	return 0;
}

static int find_local_eid_by_addr(struct ctx *ctx, struct dest_phys *dest,
				  uint32_t net, mctp_eid_t *ret_eid)
{
	mctp_eid_t local = local_addr(ctx, dest->ifindex);
	if (local == 0) {
		warnx("%s: no local address on ifindex %d", __func__,
		      dest->ifindex);
		return -EINVAL;
	}

	struct peer *peer = find_peer_by_addr(ctx, local, net);
	if (!peer || peer->state != LOCAL) {
		return -EINVAL;
	}

	*ret_eid = local;
	return 0;
}

/* Returns ptr, frees it on the next default event loop cycle (defer)*/
static void *dfree(void *ptr)
{
	sd_event *e = NULL;
	int rc;

	if (!ptr)
		return NULL;
	rc = sd_event_default(&e);
	if (rc < 0) {
		warnx("defer_free no event loop");
		goto out;
	}
	rc = sd_event_add_defer(e, NULL, defer_free_handler, ptr);
	if (rc < 0) {
		warnx("defer_free failed adding");
		goto out;
	}

out:
	if (e)
		sd_event_unref(e);
	return ptr;
}

static int cb_exit_loop_io(sd_event_source *s, int fd, uint32_t revents,
			   void *userdata)
{
	sd_event_exit(sd_event_source_get_event(s), revents);
	return 0;
}

static int cb_exit_loop_timeout(sd_event_source *s, uint64_t usec,
				void *userdata)
{
	sd_event_exit(sd_event_source_get_event(s), -ETIMEDOUT);
	return 0;
}

/* Wait for events on fd with timeout.
 * Events are EPOLLIN, EPOLLOUT, EPOLLERR etc.
 * Returns: positive value with event flags (EPOLLIN, EPOLLERR, etc.) on success
 *          negative error code on timeout (-ETIMEDOUT) or other error
 */
static int wait_fd_timeout(int fd, short events, uint64_t timeout_usec)
{
	int rc;
	sd_event *ev = NULL;

	// Create a new event loop just for the event+timeout
	rc = sd_event_new(&ev);
	if (rc < 0)
		goto out;

	rc = mctp_ops.sd_event.add_time_relative(ev, NULL, CLOCK_MONOTONIC,
						 timeout_usec, 0,
						 cb_exit_loop_timeout, NULL);
	if (rc < 0)
		goto out;

	rc = sd_event_add_io(ev, NULL, fd, events, cb_exit_loop_io, NULL);
	if (rc < 0)
		goto out;

	// TODO: maybe need to break the loop on SIGINT event too?
	rc = sd_event_loop(ev);

out:
	if (ev)
		sd_event_unref(ev);
	return rc;
}

static const char *path_from_peer(const struct peer *peer)
{
	if (!peer->published) {
		bug_warn("%s on peer %s", __func__, peer_tostr(peer));
		return NULL;
	}
	return peer->path;
}

static int get_role(const char *mode, struct role *role)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(roles); i++) {
		if (roles[i].dbus_val &&
		    (strcmp(roles[i].dbus_val, mode) == 0)) {
			memcpy(role, &roles[i], sizeof(struct role));
			return 0;
		}
	}

	return -1;
}

/* Returns the message from a socket.
   ret_buf is allocated, should be freed by the caller */
static int read_message(struct ctx *ctx, int sd, uint8_t **ret_buf,
			size_t *ret_buf_size,
			struct sockaddr_mctp_ext *ret_addr, bool suppress_logs)
{
	int rc;
	socklen_t addrlen;
	ssize_t len;
	uint8_t *buf = NULL;
	size_t buf_size = 0;

	len = mctp_ops.mctp.recvfrom(sd, NULL, 0, MSG_PEEK | MSG_TRUNC, NULL,
				     0);
	if (len < 0) {
		rc = -errno;
		goto out;
	}

	if (len == 0) {
		*ret_buf = NULL;
		*ret_buf_size = 0;
		rc = 0;
		goto out;
	}

	buf_size = len;
	buf = malloc(buf_size);
	if (!buf) {
		rc = -ENOMEM;
		goto out;
	}

	addrlen = sizeof(struct sockaddr_mctp_ext);
	memset(ret_addr, 0x0, addrlen);
	len = mctp_ops.mctp.recvfrom(sd, buf, buf_size, MSG_TRUNC,
				     (struct sockaddr *)ret_addr, &addrlen);
	if (len < 0) {
		rc = -errno;
		goto out;
	}
	if ((size_t)len != buf_size) {
		if (!suppress_logs)
			bug_warn("incorrect recvfrom %zd, expected %zu", len,
				 buf_size);
		rc = -EPROTO;
		goto out;
	}
	if (addrlen != sizeof(struct sockaddr_mctp_ext)) {
		warnx("Unexpected address size %u.", addrlen);
		rc = -EPROTO;
		goto out;
	}

	*ret_buf = buf;
	*ret_buf_size = buf_size;
	rc = 0;
out:
	if (rc < 0) {
		if (ctx->verbose && !suppress_logs) {
			warnx("read_message returned error: %s from %s len %zu",
			      strerror(-rc), ext_addr_tostr(ret_addr),
			      buf_size);
		}
		free(buf);
	}
	return rc;
}

/* Replies to a physical address */
static int reply_message_phys(struct ctx *ctx, int sd, const void *resp,
			      size_t resp_len,
			      const struct sockaddr_mctp_ext *addr)
{
	ssize_t len;
	struct sockaddr_mctp_ext reply_addr = *addr;

	reply_addr.smctp_base.smctp_tag &= ~MCTP_TAG_OWNER;

	len = mctp_ops.mctp.sendto(sd, resp, resp_len, 0,
				   (struct sockaddr *)&reply_addr,
				   sizeof(reply_addr));
	if (len < 0) {
		return -errno;
	}

	if ((size_t)len != resp_len) {
		bug_warn("short sendto %zd, expected %zu", len, resp_len);
		return -EPROTO;
	}
	return 0;
}

/* Replies to a real EID, not physical addressing */
static int reply_message(struct ctx *ctx, int sd, const void *resp,
			 size_t resp_len, const struct sockaddr_mctp_ext *addr)
{
	ssize_t len;
	struct sockaddr_mctp reply_addr;

	memcpy(&reply_addr, &addr->smctp_base, sizeof(reply_addr));
	reply_addr.smctp_tag &= ~MCTP_TAG_OWNER;

	if (reply_addr.smctp_addr.s_addr == 0 ||
	    reply_addr.smctp_addr.s_addr == 0xff) {
		bug_warn("reply_message can't take EID %d",
			 reply_addr.smctp_addr.s_addr);
		return -EPROTO;
	}

	len = mctp_ops.mctp.sendto(sd, resp, resp_len, 0,
				   (struct sockaddr *)&reply_addr,
				   sizeof(reply_addr));
	if (len < 0) {
		return -errno;
	}

	if ((size_t)len != resp_len) {
		bug_warn("short sendto %zd, expected %zu", len, resp_len);
		return -EPROTO;
	}
	return 0;
}

/// Clear interface local addresses and remote cached peers
static void clear_interface_addrs(struct ctx *ctx, int ifindex)
{
	mctp_eid_t *addrs;
	size_t addrs_num;
	size_t i;
	int rc;

	// Remove all addresses on this interface
	addrs = mctp_nl_addrs_byindex(ctx->nl, ifindex, &addrs_num);
	if (addrs) {
		for (i = 0; i < addrs_num; i++) {
			rc = mctp_nl_addr_del(ctx->nl, addrs[i], ifindex);
			if (rc < 0) {
				errx(rc,
				     "ERR: cannot remove local eid %d ifindex %d",
				     addrs[i], ifindex);
			}
		}
		free(addrs);
	}

	// Remove all peers on this interface
	for (i = 0; i < ctx->num_peers;) {
		struct peer *p = ctx->peers[i];
		if (p->state == REMOTE && p->phys.ifindex == ifindex) {
			remove_peer(p);
		} else {
			i++;
		}
	}
}

/// Handles new Incoming Set Endpoint ID request
///
/// This currently handles two cases: Top-most bus owner and Endpoint. No bridge
/// support yet.
///
///
/// # References
///
/// The DSP0236 1.3.3 specification describes Set Endpoint ID in the following
/// sections:
///
/// - 8.18  Endpoint ID assignment and endpoint ID pools
///
///   > A non-bridge device that is connected to multiple different buses
///   > will have one EID for each bus it is attached to.
///
/// - 9.1.3 EID options for MCTP bridge
///
///   > There are three general options:
///   > - The bridge uses a single MCTP endpoint
///   > - The bridge uses an MCTP endpoint for each bus that connects to a bus owner
///   > - The bridge uses an MCTP endpoint for every bus to which it connects
///
/// - 12.4  Set Endpoint ID
///
///   [the whole section]
///
static int handle_control_set_endpoint_id(struct ctx *ctx, int sd,
					  struct sockaddr_mctp_ext *addr,
					  const uint8_t *buf,
					  const size_t buf_size)
{
	struct mctp_ctrl_cmd_set_eid *req = NULL;
	struct mctp_ctrl_resp_set_eid respi = { 0 }, *resp = &respi;
	mctp_eid_t local_eid, src_eid;
	struct link *link_data;
	struct peer *peer;
	size_t resp_len;
	int rc;

	if (buf_size < sizeof(*req)) {
		bug_warn("short Set Endpoint ID message");
		return -ENOMSG;
	}
	req = (void *)buf;

	link_data = mctp_nl_get_link_userdata(ctx->nl, addr->smctp_ifindex);
	if (!link_data) {
		bug_warn("unconfigured interface %d", addr->smctp_ifindex);
		return -ENOENT;
	}

	// create route for incoming packet SRC eid
	src_eid = addr->smctp_base.smctp_addr.s_addr;
	rc = mctp_nl_route_add(ctx->nl, src_eid, 0, addr->smctp_ifindex, NULL,
			       0);
	if (rc < 0 && rc != -EEXIST) {
		warnx("failed to setup routes for incoming SRC EID %d [rc %s]",
		      src_eid, strerror(-rc));
		return -errno;
	}

	mctp_ctrl_msg_hdr_init_resp(&respi.ctrl_hdr, req->ctrl_hdr);
	resp->completion_code = MCTP_CTRL_CC_SUCCESS;
	resp_len = sizeof(struct mctp_ctrl_resp_set_eid);

	// reject if we are bus owner
	if (link_data->role == ENDPOINT_ROLE_BUS_OWNER) {
		warnx("Rejected set EID %d request from (%s) because we are the bus owner",
		      req->eid, ext_addr_tostr(addr));
		resp->completion_code = MCTP_CTRL_CC_ERROR_UNSUPPORTED_CMD;
		resp_len = sizeof(struct mctp_ctrl_resp);
		return reply_message(ctx, sd, resp, resp_len, addr);
	}

	// error if EID is invalid
	if (req->eid < 0x08 || req->eid == 0xFF) {
		warnx("Rejected invalid EID %d", req->eid);
		resp->completion_code = MCTP_CTRL_CC_ERROR_INVALID_DATA;
		resp_len = sizeof(struct mctp_ctrl_resp);
		return reply_message(ctx, sd, resp, resp_len, addr);
	}

	switch (GET_MCTP_SET_EID_OPERATION(req->operation)) {
	case MCTP_SET_EID_SET:
		// for bridges, only accept EIDs from originator bus
		//
		// We currently only support endpoints, which require separate
		// EIDs on interfaces (see function comment). For bridges, we
		// might need to support sharing a single EID for multiple
		// interfaces. We will need to:
		// - track the first bus assigned the EID.
		// - policy for propagating EID to other interfaces (see bridge
		//   EID options in function comment above)
		// - Respond with device not ready CC if not assigned already
		// - Repond with already assigned eid with no dynamic pool size

		local_eid = local_addr(ctx, addr->smctp_ifindex);
		resp->status =
			SET_MCTP_EID_ASSIGNMENT_STATUS(MCTP_SET_EID_REJECTED) |
			SET_MCTP_EID_ALLOCATION_STATUS(
				MCTP_SET_EID_POOL_RECEIVED);

		if (!local_eid) {
			resp->eid_set = 0;
			resp->completion_code = MCTP_CTRL_CC_ERROR_NOT_READY;
			return reply_message_phys(ctx, sd, resp, resp_len,
						  addr);
		} else {
			resp->eid_set = local_eid;
			resp->completion_code = MCTP_CTRL_CC_SUCCESS;
			resp->eid_pool_size = 0;
			uint8_t phyaddr_size = 0;

			/*
			Create a routing entry for BusOwner EID and
			send out Routing Info Update message to all downstream
			bridges. Failure in doing so will not be considered
			as critical error since EID assignement has already been accepted
			*/
			struct routing_info_entry copy_entry = {
				.entry_type = 0,
				.eid_range = 1,
				.first_eid = src_eid,
			};
			rc = cache_routing_info_entry(
				ctx, &copy_entry,
				routing_info_entry_size_from_phys(phyaddr_size));
			if (rc < 0) {
				warnx("Fail to update cache with entry of first eid %d",
				      src_eid);
				return reply_message(ctx, sd, resp, resp_len,
						     addr);
			}

			struct peer *sendto_peer = NULL;
			for (size_t i = 0; i < ctx->num_peers; i++) {
				sendto_peer = ctx->peers[i];
				// Only send to bridges (peers with endpoint_type as BRIDGE)
				if (GET_ENDPOINT_TYPE(
					    sendto_peer->endpoint_type) ==
				    MCTP_BUS_OWNER_BRIDGE) {
					fprintf(stderr,
						"Sending Routing Info Update for EID %d to bridge EID %d\n",
						copy_entry.first_eid,
						sendto_peer->eid);
					rc = endpoint_send_routing_info_update(
						sendto_peer,
						copy_entry.first_eid,
						copy_entry.eid_range,
						copy_entry.entry_type, 0,
						NULL);
					if (rc < 0) {
						warnx("Routing Info update failed for bridge eid %d: rc %s",
						      sendto_peer->eid,
						      strerror(-rc));
					}
				}
			}
		}

		// 5. Update bmc_ignore_eids list
		uint8_t *temp_ignore_eids = realloc(
			ctx->bmc_ignore_eids, ctx->bmc_ignore_eids_count + 1);
		if (!temp_ignore_eids) {
			warnx("Fail to update ignore eids list with entry of src eid %d",
			      src_eid);
			return -ENOMEM;
		}
		ctx->bmc_ignore_eids = temp_ignore_eids;
		ctx->bmc_ignore_eids[ctx->bmc_ignore_eids_count] = src_eid;
		ctx->bmc_ignore_eids_count += 1;
		return reply_message(ctx, sd, resp, resp_len, addr);
	case MCTP_SET_EID_FORCE:

		// Temporarily reject FORCE Set EID requests until we have a way to handle them
		resp->completion_code = MCTP_CTRL_CC_ERROR_UNSUPPORTED_CMD;
		resp_len = sizeof(struct mctp_ctrl_resp);
		return reply_message_phys(ctx, sd, resp, resp_len, addr);

		fprintf(stderr, "Trying to set EID to %d\n", req->eid);
		if (find_peer_by_addr(ctx, req->eid,
				      addr->smctp_base.smctp_network)) {
			warnx("EID %d already assigned", req->eid);
			resp->completion_code = MCTP_CTRL_CC_ERROR_INVALID_DATA;
			resp_len = sizeof(struct mctp_ctrl_resp);
			return reply_message(ctx, sd, resp, resp_len, addr);
		}

		// When we are assigned a new EID, assume our world view of the
		// network reachable from this interface has been stale. Reset
		// everything.
		clear_interface_addrs(ctx, addr->smctp_ifindex);

		rc = mctp_nl_addr_add(ctx->nl, req->eid, addr->smctp_ifindex);
		if (rc < 0) {
			warnx("ERR: cannot add local eid %d to ifindex %d",
			      req->eid, addr->smctp_ifindex);
			resp->completion_code = MCTP_CTRL_CC_ERROR_NOT_READY;
		}

		rc = add_peer_from_addr(ctx, addr, &peer);
		if (rc == 0) {
			rc = setup_added_peer(peer);
		}
		if (rc < 0) {
			warnx("ERR: cannot add bus owner to object lists");
		}

		if (link_data->discovered != DISCOVERY_UNSUPPORTED) {
			link_data->discovered = DISCOVERY_DISCOVERED;
		}
		resp->status =
			SET_MCTP_EID_ASSIGNMENT_STATUS(MCTP_SET_EID_ACCEPTED) |
			SET_MCTP_EID_ALLOCATION_STATUS(MCTP_SET_EID_POOL_NONE);
		resp->eid_set = req->eid;
		resp->eid_pool_size = 0;
		fprintf(stderr, "Accepted set eid %d\n", req->eid);
		return reply_message(ctx, sd, resp, resp_len, addr);

	case MCTP_SET_EID_DISCOVERED:
		if (link_data->discovered == DISCOVERY_UNSUPPORTED) {
			resp->completion_code = MCTP_CTRL_CC_ERROR_INVALID_DATA;
			resp_len = sizeof(struct mctp_ctrl_resp);
			return reply_message(ctx, sd, resp, resp_len, addr);
		}

		link_data->discovered = DISCOVERY_DISCOVERED;
		resp->status =
			SET_MCTP_EID_ASSIGNMENT_STATUS(MCTP_SET_EID_REJECTED) |
			SET_MCTP_EID_ALLOCATION_STATUS(MCTP_SET_EID_POOL_NONE);
		resp->eid_set = req->eid;
		resp->eid_pool_size = 0;
		return reply_message(ctx, sd, resp, resp_len, addr);

	case MCTP_SET_EID_RESET:
		// unsupported
		resp->completion_code = MCTP_CTRL_CC_ERROR_INVALID_DATA;
		return reply_message(ctx, sd, resp, resp_len, addr);

	default:
		bug_warn("unreachable Set EID operation code");
		return -EINVAL;
	}
}

static int
handle_control_get_version_support(struct ctx *ctx, int sd,
				   const struct sockaddr_mctp_ext *addr,
				   const uint8_t *buf, const size_t buf_size)
{
	struct mctp_ctrl_resp_get_mctp_ver_support *resp = NULL;
	struct mctp_ctrl_cmd_get_mctp_ver_support *req = NULL;
	size_t resp_len, i, ver_count = 0, ver_bytes_count;
	uint32_t *versions = NULL;
	uint8_t *respbuf = NULL;
	ssize_t ver_idx = -1;
	int rc;

	if (buf_size < sizeof(struct mctp_ctrl_cmd_get_mctp_ver_support)) {
		warnx("short Get Version Support message");
		return -ENOMSG;
	}

	req = (void *)buf;
	if (req->msg_type_number == 0xFF) {
		// use same version for base spec and control protocol
		req->msg_type_number = 0;
	}
	for (i = 0; i < ctx->num_supported_msg_types; i++) {
		if (ctx->supported_msg_types[i].msg_type ==
		    req->msg_type_number) {
			ver_idx = i;
			break;
		}
	}

	if (ver_idx < 0) {
		respbuf = malloc(sizeof(struct mctp_ctrl_resp));
		if (!respbuf) {
			warnx("Failed to allocate response buffer");
			return -ENOMEM;
		}
		resp = (void *)respbuf;
		// Nobody registered yet as responder for this type
		resp->completion_code =
			MCTP_CTRL_CC_GET_MCTP_VER_SUPPORT_UNSUPPORTED_TYPE;
		resp_len = sizeof(struct mctp_ctrl_resp);
	} else {
		ver_count = ctx->supported_msg_types[ver_idx].num_versions;
		ver_bytes_count = ver_count * sizeof(uint32_t);
		respbuf = malloc(sizeof(*resp) + ver_bytes_count);
		if (!respbuf) {
			warnx("Failed to allocate response buffer for versions");
			return -ENOMEM;
		}
		resp = (void *)respbuf;
		resp->number_of_entries = ver_count;
		versions = (void *)(resp + 1);
		memcpy(versions, ctx->supported_msg_types[ver_idx].versions,
		       ver_bytes_count);
		resp->completion_code = MCTP_CTRL_CC_SUCCESS;
		resp_len = sizeof(*resp) + ver_bytes_count;
	}

	mctp_ctrl_msg_hdr_init_resp(&resp->ctrl_hdr, req->ctrl_hdr);

	rc = reply_message(ctx, sd, resp, resp_len, addr);
	free(respbuf);

	return rc;
}

static int handle_control_get_endpoint_id(struct ctx *ctx, int sd,
					  const struct sockaddr_mctp_ext *addr,
					  const uint8_t *buf,
					  const size_t buf_size)
{
	struct mctp_ctrl_cmd_get_eid *req = NULL;
	struct mctp_ctrl_resp_get_eid respi = { 0 }, *resp = &respi;

	if (buf_size < sizeof(*req)) {
		warnx("short Get Endpoint ID message");
		return -ENOMSG;
	}

	req = (void *)buf;
	mctp_ctrl_msg_hdr_init_resp(&resp->ctrl_hdr, req->ctrl_hdr);

	resp->eid = local_addr(ctx, addr->smctp_ifindex);

	resp->eid_type = 0;
	if (ctx->default_role == ENDPOINT_ROLE_BUS_OWNER)
		resp->eid_type |= SET_ENDPOINT_TYPE(MCTP_BUS_OWNER_BRIDGE);
	resp->eid_type |=
		SET_ENDPOINT_ID_TYPE(MCTP_STATIC_EID_MATCHING_PRESENT);
	// TODO: medium specific information

	// Get Endpoint ID is typically send and reply using physical addressing.
	return reply_message_phys(ctx, sd, resp, sizeof(*resp), addr);
}

static int
handle_control_get_endpoint_uuid(struct ctx *ctx, int sd,
				 const struct sockaddr_mctp_ext *addr,
				 const uint8_t *buf, const size_t buf_size)
{
	struct mctp_ctrl_cmd_get_uuid *req = NULL;
	struct mctp_ctrl_resp_get_uuid respi = { 0 }, *resp = &respi;

	if (buf_size < sizeof(*req)) {
		warnx("short Get Endpoint UUID message");
		return -ENOMSG;
	}

	req = (void *)buf;
	mctp_ctrl_msg_hdr_init_resp(&resp->ctrl_hdr, req->ctrl_hdr);
	memcpy(resp->uuid, ctx->uuid, sizeof(resp->uuid));
	return reply_message(ctx, sd, resp, sizeof(*resp), addr);
}

static int handle_control_get_message_type_support(
	struct ctx *ctx, int sd, const struct sockaddr_mctp_ext *addr,
	const uint8_t *buf, const size_t buf_size)
{
	struct mctp_ctrl_resp_get_msg_type_support *resp = NULL;
	struct mctp_ctrl_cmd_get_msg_type_support *req = NULL;
	bool pcie_support = false, iana_support = false;
	size_t i, resp_len, type_count;
	uint8_t *resp_buf, *msg_types;
	int rc;

	if (buf_size < sizeof(*req)) {
		warnx("short Get Message Type Support message");
		return -ENOMSG;
	}

	req = (void *)buf;
	type_count = ctx->num_supported_msg_types;

	for (i = 0; i < ctx->num_supported_vdm_types; i++) {
		pcie_support |= ctx->supported_vdm_types[i].format ==
				VID_FORMAT_PCIE;
		iana_support |= ctx->supported_vdm_types[i].format ==
				VID_FORMAT_IANA;
	}
	type_count += (pcie_support + iana_support);

	// Allocate extra space for the message types
	resp_len = sizeof(*resp) + type_count;
	resp_buf = malloc(resp_len);
	if (!resp_buf) {
		warnx("Failed to allocate response buffer");
		return -ENOMEM;
	}

	resp = (void *)resp_buf;
	mctp_ctrl_msg_hdr_init_resp(&resp->ctrl_hdr, req->ctrl_hdr);
	resp->completion_code = MCTP_CTRL_CC_SUCCESS;

	// Append message types after msg_type_count
	msg_types = (uint8_t *)(resp + 1);
	for (i = 0; i < ctx->num_supported_msg_types; i++) {
		msg_types[i] = ctx->supported_msg_types[i].msg_type;
	}
	if (pcie_support) {
		msg_types[i++] = MCTP_TYPE_VENDOR_PCIE;
	}
	if (iana_support) {
		msg_types[i++] = MCTP_TYPE_VENDOR_IANA;
	}

	resp->msg_type_count = type_count;
	rc = reply_message(ctx, sd, resp, resp_len, addr);
	free(resp_buf);

	return rc;
}

static int
handle_control_get_vdm_type_support(struct ctx *ctx, int sd,
				    const struct sockaddr_mctp_ext *addr,
				    const uint8_t *buf, const size_t buf_size)
{
	struct mctp_ctrl_resp_get_vdm_support *resp = NULL;
	struct mctp_ctrl_cmd_get_vdm_support *req = NULL;
	size_t resp_len, max_rsp_len, vdm_count;
	struct vdm_type_support *cur_vdm;
	uint16_t *cmd_type_ptr;
	uint8_t *resp_buf;
	int rc;

	if (buf_size < sizeof(*req)) {
		warnx("short Get VDM Type Support message");
		return -ENOMSG;
	}

	req = (void *)buf;
	vdm_count = ctx->num_supported_vdm_types;
	// Allocate space for 32 bit VID + 16 bit cmd set
	max_rsp_len = sizeof(*resp) + sizeof(uint16_t);
	resp_len = max_rsp_len;
	resp_buf = malloc(max_rsp_len);
	if (!resp_buf) {
		warnx("Failed to allocate response buffer");
		return -ENOMEM;
	}
	resp = (void *)resp_buf;
	cmd_type_ptr = (uint16_t *)(resp + 1);
	mctp_ctrl_msg_hdr_init_resp(&resp->ctrl_hdr, req->ctrl_hdr);

	if (req->vendor_id_set_selector >= vdm_count) {
		if (ctx->verbose) {
			warnx("Get VDM Type Support selector %u out of range (max %zu)",
			      req->vendor_id_set_selector, vdm_count);
		}
		resp_len = sizeof(struct mctp_ctrl_resp);
		resp->completion_code = MCTP_CTRL_CC_ERROR_INVALID_DATA;
	} else {
		cur_vdm =
			&ctx->supported_vdm_types[req->vendor_id_set_selector];
		resp->completion_code = MCTP_CTRL_CC_SUCCESS;
		resp->vendor_id_set_selector = req->vendor_id_set_selector + 1;
		if (req->vendor_id_set_selector == (vdm_count - 1)) {
			resp->vendor_id_set_selector =
				MCTP_GET_VDM_SUPPORT_NO_MORE_CAP_SET;
		}
		resp->vendor_id_format = cur_vdm->format;

		if (cur_vdm->format == VID_FORMAT_PCIE) {
			// 4 bytes was reserved for VID, but PCIe VID uses only 2 bytes.
			cmd_type_ptr--;
			resp_len = max_rsp_len - sizeof(uint16_t);
			resp->vendor_id_data_pcie =
				htobe16(cur_vdm->vendor_id.pcie);
		} else {
			resp->vendor_id_data_iana =
				htobe32(cur_vdm->vendor_id.iana);
		}

		*cmd_type_ptr = htobe16(cur_vdm->cmd_set);
	}

	rc = reply_message(ctx, sd, resp, resp_len, addr);
	free(resp_buf);
	return rc;
}

static int
handle_control_resolve_endpoint_id(struct ctx *ctx, int sd,
				   const struct sockaddr_mctp_ext *addr,
				   const uint8_t *buf, const size_t buf_size)
{
	struct mctp_ctrl_cmd_resolve_endpoint_id *req = NULL;
	struct mctp_ctrl_resp_resolve_endpoint_id *resp = NULL;
	uint8_t resp_buf[sizeof(*resp) + MAX_ADDR_LEN] = { 0 };
	size_t resp_len;
	struct peer *peer = NULL;

	if (buf_size < sizeof(*req)) {
		warnx("short Resolve Endpoint ID message");
		return -ENOMSG;
	}

	req = (void *)buf;
	resp = (void *)resp_buf;
	mctp_ctrl_msg_hdr_init_resp(&resp->ctrl_hdr, req->ctrl_hdr);
	peer = find_peer_by_addr(ctx, req->eid, addr->smctp_base.smctp_network);
	if (!peer) {
		resp->completion_code = MCTP_CTRL_CC_ERROR;
		resp_len = sizeof(*resp);
	} else {
		// TODO: bridging
		resp->eid = req->eid;
		memcpy((void *)(resp + 1), peer->phys.hwaddr,
		       peer->phys.hwaddr_len);
		resp_len = sizeof(*resp) + peer->phys.hwaddr_len;
	}

	return reply_message(ctx, sd, resp, resp_len, addr);
}

static int handle_control_discovery_notify(struct ctx *ctx, int sd,
					   const struct sockaddr_mctp_ext *addr,
					   const uint8_t *buf,
					   const size_t buf_size)
{
	if (buf_size < sizeof(struct mctp_ctrl_cmd_discovery_notify)) {
		warnx("short Discovery Notify message");
		return -ENOMSG;
	}

	const struct mctp_ctrl_cmd_discovery_notify *req =
		(const struct mctp_ctrl_cmd_discovery_notify *)buf;

	struct mctp_ctrl_resp_discovery_notify resp = {
		.ctrl_hdr.command_code = MCTP_CTRL_CMD_DISCOVERY_NOTIFY,
		.ctrl_hdr.rq_dgram_inst =
			RQDI_RESP |
			(req->ctrl_hdr.rq_dgram_inst & RQDI_IID_MASK),
		.completion_code = MCTP_CTRL_CC_SUCCESS,
	};

	const char *ifname = mctp_nl_if_byindex(ctx->nl, addr->smctp_ifindex);
	if (!ifname) {
		warnx("No ifname found for %s ", ext_addr_tostr(addr));
		return -1;
	}

	if (ctx->verbose) {
		fprintf(stderr, "Received Discovery Notify from %s, EID %d \n",
			ext_addr_tostr(addr),
			addr->smctp_base.smctp_addr.s_addr);
	}

	char path[256];
	memset(path, 0, sizeof(path));
	snprintf(path, sizeof(path), "%s/%s", MCTP_DBUS_PATH_LINKS, ifname);

	/* Retry transient sd_bus_emit_signal failures before giving up.
	 * On final failure return CC_ERROR so the device retries the
	 * DiscoveryNotify, and log at warning level for field diagnosis. */
	int r = 0;
	for (int attempt = 1; attempt <= 3; attempt++) {
		r = sd_bus_emit_signal(ctx->bus, path,
				       CC_MCTP_DBUS_IFACE_BUSOWNER,
				       "DiscoveryNotify", NULL);
		if (r >= 0)
			break;
		warnx("WARNING: DiscoveryNotify emit attempt %d/3 failed: %s",
		      attempt, strerror(-r));
	}
	if (r < 0)
		resp.completion_code = MCTP_CTRL_CC_ERROR;

	if (!(req->ctrl_hdr.rq_dgram_inst & MCTP_CTRL_HDR_FLAG_DGRAM)) {
		return reply_message(ctx, sd, &resp, sizeof(resp), addr);
	}

	return 0;
}
static int handle_control_prepare_endpoint_discovery(
	struct ctx *ctx, int sd, const struct sockaddr_mctp_ext *addr,
	const uint8_t *buf, const size_t buf_size)
{
	struct mctp_ctrl_msg_hdr *req = NULL;
	struct mctp_ctrl_resp_prepare_discovery respi = { 0 }, *resp = &respi;
	struct link *link_data;

	if (buf_size < sizeof(*req)) {
		warnx("short Prepare for Endpoint Discovery message");
		return -ENOMSG;
	}

	link_data = mctp_nl_get_link_userdata(ctx->nl, addr->smctp_ifindex);
	if (!link_data) {
		bug_warn("unconfigured interface %d", addr->smctp_ifindex);
		return -ENOENT;
	}

	if (link_data->role == ENDPOINT_ROLE_BUS_OWNER) {
		// ignore message if we are bus owner
		return 0;
	}

	req = (void *)buf;
	resp = (void *)resp;
	mctp_ctrl_msg_hdr_init_resp(&resp->ctrl_hdr, *req);

	if (link_data->discovered == DISCOVERY_UNSUPPORTED) {
		warnx("received prepare for discovery request to unsupported interface %d",
		      addr->smctp_ifindex);
		resp->completion_code = MCTP_CTRL_CC_ERROR_UNSUPPORTED_CMD;
		return reply_message_phys(ctx, sd, resp,
					  sizeof(struct mctp_ctrl_resp), addr);
	}

	if (link_data->discovered == DISCOVERY_DISCOVERED) {
		link_data->discovered = DISCOVERY_UNDISCOVERED;
		warnx("clear discovered flag of interface %d",
		      addr->smctp_ifindex);
	}

	// we need to send using physical addressing, no entry in routing table yet
	resp->completion_code = MCTP_CTRL_CC_SUCCESS;
	return reply_message_phys(ctx, sd, resp, sizeof(*resp), addr);
}

static int
handle_control_endpoint_discovery(struct ctx *ctx, int sd,
				  const struct sockaddr_mctp_ext *addr,
				  const uint8_t *buf, const size_t buf_size)
{
	struct mctp_ctrl_msg_hdr *req = NULL;
	struct mctp_ctrl_resp_endpoint_discovery respi = { 0 }, *resp = &respi;
	struct link *link_data;

	if (buf_size < sizeof(*req)) {
		warnx("short Endpoint Discovery message");
		return -ENOMSG;
	}

	link_data = mctp_nl_get_link_userdata(ctx->nl, addr->smctp_ifindex);
	if (!link_data) {
		bug_warn("unconfigured interface %d", addr->smctp_ifindex);
		return -ENOENT;
	}

	if (link_data->role == ENDPOINT_ROLE_BUS_OWNER) {
		// ignore message if we are bus owner
		return 0;
	}

	if (link_data->discovered == DISCOVERY_UNSUPPORTED) {
		resp->completion_code = MCTP_CTRL_CC_ERROR_INVALID_DATA;
		return reply_message(ctx, sd, resp,
				     sizeof(struct mctp_ctrl_resp), addr);
	}

	if (link_data->discovered == DISCOVERY_DISCOVERED) {
		// if we are already discovered (i.e, assigned an EID), then no reply
		return 0;
	}

	req = (void *)buf;
	resp = (void *)resp;
	mctp_ctrl_msg_hdr_init_resp(&resp->ctrl_hdr, *req);

	// we need to send using physical addressing, no entry in routing table yet
	return reply_message_phys(ctx, sd, resp, sizeof(*resp), addr);
}

static int handle_control_unsupported(struct ctx *ctx, int sd,
				      const struct sockaddr_mctp_ext *addr,
				      const uint8_t *buf, const size_t buf_size)
{
	struct mctp_ctrl_msg_hdr *req = NULL;
	struct mctp_ctrl_generic {
		struct mctp_ctrl_msg_hdr ctrl_hdr;
		uint8_t completion_code;
	} __attribute__((__packed__));
	struct mctp_ctrl_generic respi = { 0 }, *resp = &respi;

	if (buf_size < sizeof(*req)) {
		warnx("short unsupported control message");
		return -ENOMSG;
	}

	req = (void *)buf;
	mctp_ctrl_msg_hdr_init_resp(&resp->ctrl_hdr, *req);
	resp->completion_code = MCTP_CTRL_CC_ERROR_UNSUPPORTED_CMD;
	return reply_message(ctx, sd, resp, sizeof(*resp), addr);
}

// Assumption: Incoming Routing Info Update message contains only single entry
// with single EID from bus owner.
static int
handle_control_routing_info_update(struct ctx *ctx, int sd,
				   const struct sockaddr_mctp_ext *addr,
				   const uint8_t *buf, const size_t buf_size)
{
	struct mctp_ctrl_cmd_routing_info_update *req = NULL;
	const struct routing_info_entry *entry = NULL;
	struct mctp_ctrl_resp resp = {};
	struct peer *local_peer = NULL;
	mctp_eid_t local_eid = 0;
	size_t entry_size = 0;
	size_t phyaddr_size = 0;
	size_t resp_len;
	int rc = 0;

	if (buf_size <
	    offsetof(struct mctp_ctrl_cmd_routing_info_update, entries)) {
		warnx("short Routing Information Update message");
		return -ENOMSG;
	}

	req = (void *)buf;
	mctp_ctrl_msg_hdr_init_resp(&resp.ctrl_hdr, req->ctrl_hdr);
	resp.completion_code = MCTP_CTRL_CC_SUCCESS;

	rc = routing_info_update_get_single_entry(req, buf_size, &entry,
						  &entry_size, &phyaddr_size);
	if (rc == -ENOMSG) {
		warnx("short Routing Information Update entry payload");
		return rc;
	}
	if (rc < 0) {
		warnx("Invalid Routing Information Update entry payload");
		resp.completion_code = MCTP_CTRL_CC_ERROR_INVALID_DATA;
		goto out;
	}

	struct link *link_data;
	link_data = mctp_nl_get_link_userdata(ctx->nl, addr->smctp_ifindex);
	if (!link_data) {
		bug_warn("unconfigured interface %d", addr->smctp_ifindex);
		return -ENOENT;
	}

	if (link_data->role == ENDPOINT_ROLE_BUS_OWNER) {
		warnx("Rejected Routing Info Update because we are the bus owner");
		resp.completion_code = MCTP_CTRL_CC_ERROR_UNSUPPORTED_CMD;
		goto out;
	}

	local_eid = local_addr(ctx, addr->smctp_ifindex);
	local_peer = find_peer_by_addr(ctx, local_eid,
				       addr->smctp_base.smctp_network);
	if (!local_peer || !local_eid) {
		warnx("Missing Gateway local eid peer configuration?");
		resp.completion_code = MCTP_CTRL_CC_ERROR;
		goto out;
	}

	// 1. Parse routing entries from the request
	uint8_t entry_type = entry->entry_type & 0x0F;
	uint8_t eid_range = entry->eid_range;
	mctp_eid_t first_eid = entry->first_eid;
	if (!mctp_eid_is_valid_unicast(first_eid) || eid_range == 0) {
		warnx("Invalid Routing Information Update EID range %d+%d",
		      first_eid, eid_range);
		resp.completion_code = MCTP_CTRL_CC_ERROR_INVALID_DATA;
		goto out;
	}

	// The advertised EID may already be a known endpoint on this network --
	// our own local EID, a downstream bridge, or a directly discovered
	// endpoint. In that case we already have routing for it, so re-adding a
	// route, forwarding the update to downstream bridges, or caching the
	// entry would be redundant and can create routing loops. Ignore the
	// entry entirely; the command is still acknowledged with success.
	if (find_peer_by_addr(ctx, first_eid,
			      addr->smctp_base.smctp_network)) {
		if (ctx->verbose)
			fprintf(stderr,
				"Ignoring Routing Info Update for EID %d: already a known endpoint\n",
				first_eid);
		goto out;
	}

	// 2. create local route for first_eid
	rc = mctp_nl_route_add(ctx->nl, first_eid, 0, addr->smctp_ifindex, NULL,
			       local_peer->mtu);
	if (rc < 0 && rc != -EEXIST) {
		warnx("failed to setup routes for first eid %d from"
		      "local if eid %d rc %s",
		      first_eid, local_eid, strerror(-rc));
		resp.completion_code = MCTP_CTRL_CC_ERROR;
		goto out;
	}

	// 3. send the same routing data to all downstream bridges
	struct peer *sendto_peer = NULL;

	for (size_t i = 0; i < ctx->num_peers; i++) {
		sendto_peer = ctx->peers[i];

		if (GET_ENDPOINT_TYPE(sendto_peer->endpoint_type) ==
		    MCTP_BUS_OWNER_BRIDGE) {
			fprintf(stderr,
				"Sending Routing Info Update for EID %d to bridge EID %d\n",
				first_eid, sendto_peer->eid);

			/* DSP0236: 12.11 Routing Information Update
			  The Routing Information Update message is used by
			  a bus owner to give routing information to a bridge
			  for the bus on which the message is being received.
			  Because the physical address format is based on the
			  bus over which the request is delivered, the bus
			  owner shall use the medium-specific physical address
			  format for the addresses sent using this command.
			 */

			/*
			  * Note: Currently, all bridges are assumed to operate on USB buses,
			  * which do not utilize a physical address. If future platforms introduce
			  * bridges on buses that support medium-specific physical addresses,
			  * this logic must be updated to use the Bus owner's physical
			  * address corresponding to the bus on which the bridge is connected.
			  */
			rc = endpoint_send_routing_info_update(
				sendto_peer, first_eid, eid_range, entry_type,
				0, NULL);
			if (rc < 0) {
				warnx("Routing Info update failed for bridge eid %d: rc %s",
				      sendto_peer->eid, strerror(-rc));
			}
		}
	}

	// 4. Update routing info entry cache
	rc = cache_routing_info_entry(ctx, entry, entry_size);
	if (rc < 0) {
		warnx("Fail to update cache with entry of first eid %d",
		      first_eid);
		goto out;
	}

	// 5. Update bmc_ignore_eids list
	uint8_t *temp_ignore_eids =
		realloc(ctx->bmc_ignore_eids, ctx->bmc_ignore_eids_count + 1);
	if (!temp_ignore_eids) {
		warnx("Fail to update ignore eids list with entry of first eid %d",
		      first_eid);
		goto out;
	}
	ctx->bmc_ignore_eids = temp_ignore_eids;
	ctx->bmc_ignore_eids[ctx->bmc_ignore_eids_count] = first_eid;
	ctx->bmc_ignore_eids_count += 1;

out:
	resp_len = sizeof(resp);
	return reply_message(ctx, sd, &resp, resp_len, addr);
}

/* Handle Get Routing Table Entries command
 * Assumes that each GRTE message contains 1 entry only.
 */
static int handle_control_get_routing_table_entries(
	struct ctx *ctx, int sd, const struct sockaddr_mctp_ext *addr,
	const uint8_t *buf, const size_t buf_size)
{
	struct mctp_ctrl_cmd_get_routing_table *req = NULL;
	struct mctp_ctrl_resp_get_routing_table *resp = NULL;
	uint8_t respbuf[sizeof(*resp) + sizeof(struct get_routing_table_entry) +
			MAX_ADDR_LEN] = { 0 };
	size_t resp_len;

	if (buf_size < sizeof(struct mctp_ctrl_cmd_get_routing_table)) {
		warnx("short Get Routing Table Entries message");
		return -ENOMSG;
	}

	req = (void *)buf;
	uint8_t entry = req->entry_handle;

	resp = (void *)respbuf;
	mctp_ctrl_msg_hdr_init_resp(&resp->ctrl_hdr, req->ctrl_hdr);
	if (entry == 0xFF || entry >= ctx->num_peers) {
		resp->completion_code = MCTP_CTRL_CC_ERROR_INVALID_DATA;
		resp->next_entry_handle = 0x00;
		resp->number_of_entries = 0;
		resp_len = sizeof(*resp) - 1;
		return reply_message(ctx, sd, resp, resp_len, addr);
	}

	struct peer *target_peer = NULL;
	size_t target_peer_idx = 0;
	uint8_t remote_count = 0;

	for (size_t i = 0; i < ctx->num_peers; i++) {
		struct peer *peer = ctx->peers[i];
		if (peer->state != REMOTE)
			continue;

		if (remote_count == entry) {
			target_peer = peer;
			target_peer_idx = i;
			break;
		}
		remote_count++;
	}

	if (target_peer == NULL) {
		resp->completion_code = MCTP_CTRL_CC_ERROR_INVALID_DATA;
		resp->next_entry_handle = 0xFF;
		resp->number_of_entries = 0;
		resp_len = sizeof(*resp) -
			   sizeof(struct get_routing_table_entry) - 1;
		return reply_message(ctx, sd, resp, resp_len, addr);
	}

	struct get_routing_table_entry *rt_entry =
		(void *)(resp->routing_entries);
	if (target_peer->routing_table_entry) {
		/* Target peer is a downstream endpoint behind a bridge - copy its routing entry */
		struct get_routing_table_entry *src =
			target_peer->routing_table_entry;
		uint8_t phys_addr_size = src->phys_address_size;

		if (phys_addr_size > MAX_ADDR_LEN)
			phys_addr_size = MAX_ADDR_LEN;

		memcpy(rt_entry, src, sizeof(*rt_entry));
		rt_entry->phys_address_size = phys_addr_size;

		if (phys_addr_size > 0) {
			uint8_t *src_phys_addr =
				(uint8_t *)(&src->phys_address_size + 1);
			uint8_t *dst_phys_addr =
				(uint8_t *)(&rt_entry->phys_address_size + 1);
			memcpy(dst_phys_addr, src_phys_addr, phys_addr_size);
		}
	} else {
		/* Direct peer*/
		const char *ifname =
			mctp_nl_if_byindex(ctx->nl, target_peer->phys.ifindex);
		const char *binding_str = get_binding_from_ifname(ifname);
		rt_entry->eid_range_size = 1;
		rt_entry->starting_eid = target_peer->eid;
		rt_entry->entry_type =
			SET_ROUTING_ENTRY_PORT(get_port_from_ifname(ifname)) |
			SET_ROUTING_ENTRY_ASSIGNMENT_TYPE(
				MCTP_STATIC_ASSIGNMENT) |
			SET_ROUTING_ENTRY_TYPE(
				GET_ENDPOINT_TYPE(target_peer->endpoint_type) ==
						MCTP_BUS_OWNER_BRIDGE ?
					MCTP_ROUTING_ENTRY_BRIDGE :
					MCTP_ROUTING_ENTRY_ENDPOINT);
		rt_entry->phys_transport_binding_id =
			get_binding_id_from_string(binding_str);
		rt_entry->phys_media_type_id =
			get_media_type_id_from_string(binding_str);
		// keep phys_address size as 1 for USB and SPI as well similar to earlier implementation in FPGA.
		rt_entry->phys_address_size =
			(strncmp(binding_str, "I3C", sizeof("I3C") - 1) == 0) ?
				6 :
				1;
		if (rt_entry->phys_address_size > 0) {
			uint8_t *src_phys_addr = target_peer->phys.hwaddr;
			uint8_t *dst_phys_addr =
				(uint8_t *)(&rt_entry->phys_address_size + 1);
			memcpy(dst_phys_addr, src_phys_addr,
			       rt_entry->phys_address_size);
		}
	}

	resp->completion_code = MCTP_CTRL_CC_SUCCESS;
	resp->number_of_entries = 1;

	/* Check if there's another REMOTE peer after this one */
	bool has_more_remote = false;
	for (size_t i = target_peer_idx + 1; i < ctx->num_peers; i++) {
		if (ctx->peers[i]->state == REMOTE) {
			has_more_remote = true;
			break;
		}
	}

	resp->next_entry_handle = has_more_remote ? (entry + 1) : 0xFF;

	resp_len = sizeof(*resp) + sizeof(struct get_routing_table_entry) +
		   rt_entry->phys_address_size - 1;
	return reply_message(ctx, sd, resp, resp_len, addr);
}

static int cb_listen_control_msg(sd_event_source *s, int sd, uint32_t revents,
				 void *userdata)
{
	struct sockaddr_mctp_ext addr = { 0 };
	struct ctx *ctx = userdata;
	uint8_t *buf = NULL;
	size_t buf_size;
	struct mctp_ctrl_msg_hdr *ctrl_msg = NULL;
	int rc;

	/* Handle error queue events first */
	if (revents & EPOLLERR) {
		/* If only error event, return early */
		if (!(revents & EPOLLIN))
			return 0;
	}

	/* Handle normal incoming messages */
	if (!(revents & EPOLLIN))
		return 0;

	/* Main control socket dispatcher: no peer context yet, never suppress. */
	rc = read_message(ctx, sd, &buf, &buf_size, &addr, false);
	if (rc < 0)
		goto out;

	if (buf_size == 0)
		errx(EXIT_FAILURE, "Control socket returned EOF");

	if (addr.smctp_base.smctp_type != MCTP_CTRL_HDR_MSG_TYPE) {
		bug_warn("Wrong message type for listen socket");
		rc = -EINVAL;
		goto out;
	}

	if (buf_size < sizeof(struct mctp_ctrl_msg_hdr)) {
		warnx("Short message %zu bytes from %s", buf_size,
		      ext_addr_tostr(&addr));
		rc = -EINVAL;
		goto out;
	}

	ctrl_msg = (void *)buf;
	if (ctx->verbose) {
		warnx("Got control request command code %hhd",
		      ctrl_msg->command_code);
	}
	switch (ctrl_msg->command_code) {
	case MCTP_CTRL_CMD_GET_VERSION_SUPPORT:
		rc = handle_control_get_version_support(ctx, sd, &addr, buf,
							buf_size);
		break;
	case MCTP_CTRL_CMD_SET_ENDPOINT_ID:
		rc = handle_control_set_endpoint_id(ctx, sd, &addr, buf,
						    buf_size);
		break;
	case MCTP_CTRL_CMD_GET_ENDPOINT_ID:
		rc = handle_control_get_endpoint_id(ctx, sd, &addr, buf,
						    buf_size);
		break;
	case MCTP_CTRL_CMD_GET_ENDPOINT_UUID:
		rc = handle_control_get_endpoint_uuid(ctx, sd, &addr, buf,
						      buf_size);
		break;
	case MCTP_CTRL_CMD_GET_MESSAGE_TYPE_SUPPORT:
		rc = handle_control_get_message_type_support(ctx, sd, &addr,
							     buf, buf_size);
		break;
	case MCTP_CTRL_CMD_GET_VENDOR_MESSAGE_SUPPORT:
		rc = handle_control_get_vdm_type_support(ctx, sd, &addr, buf,
							 buf_size);
		break;
	case MCTP_CTRL_CMD_RESOLVE_ENDPOINT_ID:
		rc = handle_control_resolve_endpoint_id(ctx, sd, &addr, buf,
							buf_size);
		break;
	case MCTP_CTRL_CMD_DISCOVERY_NOTIFY:
		rc = handle_control_discovery_notify(ctx, sd, &addr, buf,
						     buf_size);
		break;
	case MCTP_CTRL_CMD_ROUTING_INFO_UPDATE:
		rc = handle_control_routing_info_update(ctx, sd, &addr, buf,
							buf_size);
		break;
	case MCTP_CTRL_CMD_GET_ROUTING_TABLE_ENTRIES:
		rc = handle_control_get_routing_table_entries(ctx, sd, &addr,
							      buf, buf_size);
		break;
	case MCTP_CTRL_CMD_PREPARE_ENDPOINT_DISCOVERY:
		rc = handle_control_prepare_endpoint_discovery(ctx, sd, &addr,
							       buf, buf_size);
		break;
	case MCTP_CTRL_CMD_ENDPOINT_DISCOVERY:
		rc = handle_control_endpoint_discovery(ctx, sd, &addr, buf,
						       buf_size);
		break;
	default:
		if (ctx->verbose) {
			warnx("Ignoring unsupported command code 0x%02x",
			      ctrl_msg->command_code);
			rc = -ENOTSUP;
		}
		rc = handle_control_unsupported(ctx, sd, &addr, buf, buf_size);
	}

	if (ctx->verbose && rc < 0) {
		warnx("Error handling command code %02x from %s: %s",
		      ctrl_msg->command_code, ext_addr_tostr(&addr),
		      strerror(-rc));
	}

out:
	free(buf);
	return 0;
}

static int listen_control_msg(struct ctx *ctx, uint32_t net)
{
	struct sockaddr_mctp addr = { 0 };
	int rc, sd = -1, val;

	sd = mctp_ops.mctp.socket();
	if (sd < 0) {
		rc = -errno;
		warn("%s: socket() failed", __func__);
		goto out;
	}

	addr.smctp_family = AF_MCTP;
	addr.smctp_network = net;
	addr.smctp_addr.s_addr = MCTP_ADDR_ANY;
	addr.smctp_type = MCTP_CTRL_HDR_MSG_TYPE;
	addr.smctp_tag = MCTP_TAG_OWNER;

	rc = mctp_ops.mctp.bind(sd, (struct sockaddr *)&addr, sizeof(addr));
	if (rc < 0) {
		rc = -errno;
		warn("%s: bind() failed", __func__);
		goto out;
	}

	val = 1;
	rc = mctp_ops.mctp.setsockopt(sd, SOL_MCTP, MCTP_OPT_ADDR_EXT, &val,
				      sizeof(val));
	if (rc < 0) {
		rc = -errno;
		warn("Kernel does not support MCTP extended addressing");
		goto out;
	}

	/* Enable error queue for transport error reporting */
	val = 1;
	rc = mctp_ops.mctp.setsockopt(sd, SOL_MCTP, MCTP_OPT_ENABLE_ERRQUEUE,
				      &val, sizeof(val));
	if (rc < 0) {
		/* Not fatal if kernel doesn't support it */
		if (ctx->verbose)
			warnx("MCTP error queue not supported by kernel");
	} else {
		if (ctx->verbose)
			fprintf(stderr,
				"MCTP error queue enabled on control socket fd %d, network %u\n",
				sd, net);
	}

	/* Register for both normal messages and error queue events */
	rc = sd_event_add_io(ctx->event, NULL, sd, EPOLLIN | EPOLLERR,
			     cb_listen_control_msg, ctx);
	if (rc < 0)
		goto out;

	return 0;

out:
	if (rc < 0) {
		close(sd);
	}
	return rc;
}

static void log_mctp_error(struct ctx *ctx, const struct mctp_error *err,
			   const char *ifname)
{
	uint8_t command_code = 0;

	/* Extract command code for control messages */
	if (err->msg_type == MCTP_CTRL_HDR_MSG_TYPE && err->payload_len >= 2) {
		command_code = err->payload[1];
	}

	/* Emit TransportError D-Bus signal if we have a bus connection */
	if (ctx && ctx->bus) {
		/* Find the interface path - use the first link for simplicity */
		const char *path = MCTP_DBUS_PATH_LINKS; /* Use base path */

		int rc = sd_bus_emit_signal(
			ctx->bus, path, CC_MCTP_DBUS_IFACE_BUSOWNER,
			"TransportError", "uyyyyyyys", err->error_code,
			err->direction, err->binding, err->src_eid,
			err->dest_eid, err->tag, err->msg_type, command_code,
			ifname ? ifname : "");
		if (rc < 0) {
			warnx("Failed to emit TransportError signal: %s",
			      strerror(-rc));
		}
	}
}

static const char *resolve_ifname(struct ctx *ctx, int ifindex)
{
	const char *ifname = NULL;

	if (ifindex > 0) {
		ifname = mctp_nl_if_byindex(ctx->nl, ifindex);

		if (!ifname) {
			static char fallback[IF_NAMESIZE];
			if (if_indextoname(ifindex, fallback)) {
				ifname = fallback;
			}
		}
	}
	return ifname;
}

static int read_mctp_error_queue(struct ctx *ctx, int fd, bool verbose,
				 const struct sockaddr_mctp_ext *req_addr)
{
	char control_buf[512];
	struct mctp_error err_data; /* Buffer to receive error data from kernel */
	struct iovec iov = { .iov_base = &err_data, /* Point to our buffer */
			     .iov_len = sizeof(err_data) };
	struct msghdr msg = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = control_buf,
		.msg_controllen = sizeof(control_buf),
	};
	struct cmsghdr *cmsg;
	int ret;
	bool found_error = false;
	int cmsg_count = 0;

	ret = recvmsg(fd, &msg, MSG_ERRQUEUE | MSG_DONTWAIT);
	if (ret < 0) {
		int saved_errno = errno;
		if (saved_errno != EAGAIN && saved_errno != EWOULDBLOCK) {
			fprintf(stderr,
				">>> recvmsg(MSG_ERRQUEUE) FAILED: errno=%d (%s)\n",
				saved_errno, strerror(saved_errno));
			fflush(stderr);
			warnx("recvmsg(MSG_ERRQUEUE) failed on fd %d: %s (%d)",
			      fd, strerror(saved_errno), saved_errno);
		} else {
			/* No errors to process, which is expected in non-blocking mode */
		}
		return -1;
	}

	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL;
	     cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		cmsg_count++;

		if (cmsg->cmsg_level == SOL_MCTP &&
		    cmsg->cmsg_type == MCTP_RECVERR) {
			const char *ifname = NULL;
			int ifindex = 0;

			/* Swap src_eid and dest_eid for RX errors to correctly
			 * attribute the failing peer in the resulting TransportError
			 * D-Bus signal (and thus in any Redfish event generated by
			 * dbus-sensors). See NVBug 6137348.*/
			if (err_data.direction == MCTP_DIR_RX) {
				uint8_t tmp = err_data.src_eid;
				err_data.src_eid = err_data.dest_eid;
				err_data.dest_eid = tmp;
			}

			/* Try to get ifindex from request address if provided */
			if (req_addr && req_addr->smctp_ifindex > 0) {
				ifindex = req_addr->smctp_ifindex;
			}
			/* Otherwise try to find peer by destination EID */
			else if (err_data.dest_eid != 0) {
				/* Prefer the network from the request address
				 * if available; fall back to 1 only when the
				 * caller didn't supply a network context. */
				uint32_t net =
					(req_addr &&
					 req_addr->smctp_base.smctp_network) ?
						req_addr->smctp_base
							.smctp_network :
						1;
				struct peer *peer = find_peer_by_addr(
					ctx, err_data.dest_eid, net);
				if (peer && peer->state == REMOTE &&
				    peer->phys.ifindex > 0) {
					ifindex = peer->phys.ifindex;
				}
			}

			/* Now try to get interface name from ifindex */
			ifname = resolve_ifname(ctx, ifindex);

			if (ifname) {
				const char *binding_str =
					get_binding_from_ifname(ifname);

				if (strncmp(binding_str, "SMBus",
					    sizeof("SMBus") - 1) == 0)
					err_data.binding =
						MCTP_PHYS_BINDING_SMBUS;
				else if (strncmp(binding_str, "USB",
						 sizeof("USB") - 1) == 0)
					err_data.binding =
						MCTP_PHYS_BINDING_USB;
				else if (strncmp(binding_str, "I3C",
						 sizeof("I3C") - 1) == 0)
					err_data.binding =
						MCTP_PHYS_BINDING_I3C;
			}

			log_mctp_error(ctx, &err_data, ifname);
			found_error = true;
		}
	}

	if (cmsg_count == 0) {
		fprintf(stderr, ">>> No control messages found in msg\n");
	}

	if (!found_error) {
		fprintf(stderr,
			">>> recvmsg succeeded but no MCTP_RECVERR found (processed %d cmsgs)\n",
			cmsg_count);
		return -1;
	}

	return 0;
}

static int cb_listen_monitor(sd_event_source *s, int sd, uint32_t revents,
			     void *userdata)
{
	struct ctx *ctx = userdata;
	mctp_nl_change *changes = NULL;
	size_t num_changes;
	int rc;
	bool any_error = false;

	rc = mctp_nl_handle_monitor(ctx->nl, &changes, &num_changes);
	if (rc < 0) {
		warnx("Error handling update from netlink, link state may now be outdated. %s",
		      strerror(-rc));
		return rc;
	}

	for (size_t i = 0; i < num_changes; i++) {
		struct mctp_nl_change *c = &changes[i];
		switch (c->op) {
		case MCTP_NL_ADD_LINK: {
			rc = add_interface_local(ctx, c->ifindex);
			any_error |= (rc < 0);
			break;
		}

		case MCTP_NL_DEL_LINK: {
			// Local addresses have already been deleted with DEL_EID
			if (c->link_userdata) {
				rc = del_interface(c->link_userdata);
			} else {
				// Would have expected to have seen it in previous
				// MCTP_NL_ADD_LINK or setup_nets().
				rc = -ENOENT;
				bug_warn("delete unconfigured interface %d",
					 c->ifindex);
			}
			any_error |= (rc < 0);
			break;
		}

		case MCTP_NL_CHANGE_NET: {
			// Local addresses have already been deleted with DEL_EID
			rc = add_interface_local(ctx, c->ifindex);
			any_error |= (rc < 0);

			// Move remote endpoints
			rc = change_net_interface(ctx, c->ifindex, c->old_net);
			any_error |= (rc < 0);

			break;
		}

		case MCTP_NL_CHANGE_NAME: {
			if (c->link_userdata) {
				rc = rename_interface(ctx, c->link_userdata,
						      c->ifindex);
			} else {
				rc = -ENOENT;
				bug_warn(
					"name change for unconfigured interface %d",
					c->ifindex);
			}

			any_error |= (rc < 0);
			break;
		}

		case MCTP_NL_ADD_EID: {
			uint32_t net = mctp_nl_net_byindex(ctx->nl, c->ifindex);
			rc = add_local_eid(ctx, net, c->eid);
			any_error |= (rc < 0);
			break;
		}

		case MCTP_NL_DEL_EID: {
			rc = del_local_eid(ctx, c->old_net, c->eid);
			any_error |= (rc < 0);
			break;
		}

		case MCTP_NL_CHANGE_UP: {
			// 'up' state is currently unused
			break;
		}
		default:
			bug_warn("Unhandled netlink change type %d", c->op);
		}
	}

	if (ctx->verbose && any_error) {
		warnx("Error handling netlink update");
		mctp_nl_changes_dump(ctx->nl, changes, num_changes);
		mctp_nl_linkmap_dump(ctx->nl);
	}

	free(changes);
	return 0;
}

static int listen_monitor(struct ctx *ctx)
{
	int rc, sd;

	sd = mctp_nl_monitor(ctx->nl, true);
	if (sd < 0) {
		return sd;
	}

	rc = sd_event_add_io(ctx->event, NULL, sd, EPOLLIN, cb_listen_monitor,
			     ctx);
	return rc;
}

static uint8_t mctp_next_iid(struct ctx *ctx)
{
	uint8_t iid = ctx->iid;

	ctx->iid = (iid + 1) & RQDI_IID_MASK;
	return iid;
}

// Checks if given EID belongs to any bridge's pool range
static bool is_eid_in_bridge_pool(const struct net *n, const struct ctx *ctx,
				  mctp_eid_t eid, struct peer **pool_owner_peer)
{
	for (int i = ctx->dyn_eid_min; i <= eid; i++) {
		struct peer *peer = n->peers[i];
		if (peer && peer->pool_size > 0) {
			if (peer->eid == eid) {
				continue;
			}
			if (peer->static_pool_eids) {
				// This is static pool bridge, no point in checking here as any eid
				// could be part of its pool space [8-254], simply avoid this.
				continue;
			}
			if (eid >= peer->pool_start &&
			    eid < peer->pool_start + peer->pool_size) {
				if (pool_owner_peer)
					*pool_owner_peer = peer;
				return true;
			}
			i += peer->pool_size;
		}
	}
	return false;
}

static const char *command_str(uint8_t cmd)
{
	static char unknown_cmd_str[32];

	switch (cmd) {
	case MCTP_CTRL_CMD_SET_ENDPOINT_ID:
		return "Set Endpoint ID";
	case MCTP_CTRL_CMD_GET_ENDPOINT_ID:
		return "Get Endpoint ID";
	case MCTP_CTRL_CMD_GET_ENDPOINT_UUID:
		return "Get Endpoint UUID";
	case MCTP_CTRL_CMD_GET_VERSION_SUPPORT:
		return "Get Version Support";
	case MCTP_CTRL_CMD_GET_MESSAGE_TYPE_SUPPORT:
		return "Get Message Type Support";
	case MCTP_CTRL_CMD_GET_VENDOR_MESSAGE_SUPPORT:
		return "Get Vendor Message Support";
	case MCTP_CTRL_CMD_RESOLVE_ENDPOINT_ID:
		return "Resolve Endpoint ID";
	case MCTP_CTRL_CMD_ALLOCATE_ENDPOINT_IDS:
		return "Allocate Endpoint ID ";
	case MCTP_CTRL_CMD_ROUTING_INFO_UPDATE:
		return "Routing Info Update";
	case MCTP_CTRL_CMD_GET_ROUTING_TABLE_ENTRIES:
		return "Get Routing Table Entries";
	case MCTP_CTRL_CMD_PREPARE_ENDPOINT_DISCOVERY:
		return "Prepare Endpoint Discovery";
	case MCTP_CTRL_CMD_ENDPOINT_DISCOVERY:
		return "Endpoint Discovery";
	case MCTP_CTRL_CMD_DISCOVERY_NOTIFY:
		return "Discovery Notify";
	case MCTP_CTRL_CMD_GET_NETWORK_ID:
		return "Get Network ID";
	case MCTP_CTRL_CMD_QUERY_HOP:
		return "Query Hop";
	case MCTP_CTRL_CMD_RESOLVE_UUID:
		return "Resolve UUID";
	case MCTP_CTRL_CMD_QUERY_RATE_LIMIT:
		return "Query Rate Limit";
	case MCTP_CTRL_CMD_REQUEST_TX_RATE_LIMIT:
		return "Request TX Rate Limit";
	case MCTP_CTRL_CMD_UPDATE_RATE_LIMIT:
		return "Update Rate Limit";
	case MCTP_CTRL_CMD_QUERY_SUPPORTED_INTERFACES:
		return "Query Supported Interfaces";
	}

	sprintf(unknown_cmd_str, "Unknown command [0x%02x]", cmd);

	return unknown_cmd_str;
}

static const char *peer_cmd_prefix(const char *peer, uint8_t cmd)
{
	static char pfx_str[64];

	snprintf(pfx_str, sizeof(pfx_str), "[peer %s, cmd %s]", peer,
		 command_str(cmd));

	return pfx_str;
}

/* Common method to print response data
 * Avoid journal flooding by using only on failure path
 */
static int mctp_ctrl_print_response(uint8_t *resp_buf, size_t rsp_size,
				    struct sockaddr_mctp_ext *resp_addr,
				    bool suppress_logs)
{
	if (!suppress_logs) {
		fprintf(stderr,
			"Response received from socket %s len %zu\nbuffer: ",
			ext_addr_tostr(resp_addr), rsp_size);
		mctp_hexdump(resp_buf, rsp_size, "");
	}
	return 0;
}

/* Common checks for responses: that we have enough data for a response,
 * the expected IID and opcode, and that the response indicated success.
 */
static int mctp_ctrl_validate_response(uint8_t *buf, size_t rsp_size,
				       size_t exp_size, const char *peer,
				       uint8_t iid, uint8_t cmd,
				       struct sockaddr_mctp_ext *resp_addr,
				       bool suppress_logs)
{
	struct mctp_ctrl_resp *rsp;

	if (exp_size <= sizeof(*rsp)) {
		warnx("invalid expected response size!");
		return -EINVAL;
	}

	/* Error responses only need to include the completion code */
	if (rsp_size < MCTP_CTRL_ERROR_RESP_LEN) {
		if (!suppress_logs) {
			warnx("%s: Wrong reply length (%zu bytes)",
			      peer_cmd_prefix(peer, cmd), rsp_size);
		}
		return -ENOMSG;
	}

	/* we have enough for the smallest common response message */
	rsp = (void *)buf;

	if ((rsp->ctrl_hdr.rq_dgram_inst & RQDI_IID_MASK) != iid) {
		if (!suppress_logs) {
			warnx("%s: Wrong IID (0x%02x, expected 0x%02x)",
			      peer_cmd_prefix(peer, cmd),
			      rsp->ctrl_hdr.rq_dgram_inst & RQDI_IID_MASK, iid);
			mctp_ctrl_print_response(buf, rsp_size, resp_addr,
						 suppress_logs);
		}
		return -ENOMSG;
	}

	if (rsp->ctrl_hdr.command_code != cmd) {
		if (!suppress_logs) {
			warnx("%s: Wrong opcode (0x%02x) in response",
			      peer_cmd_prefix(peer, cmd), rsp->ctrl_hdr.command_code);
			mctp_ctrl_print_response(buf, rsp_size, resp_addr,
						 suppress_logs);
		}
		return -ENOMSG;
	}

	if (rsp->completion_code) {
		if (!suppress_logs) {
			warnx("%s: Command failed, completion code 0x%02x",
			      peer_cmd_prefix(peer, cmd), rsp->completion_code);
			mctp_ctrl_print_response(buf, rsp_size, resp_addr,
						 suppress_logs);
		}
		if (rsp->completion_code == MCTP_CTRL_CC_ERROR_UNSUPPORTED_CMD)
			return -ENOTSUP;
		return -ECONNREFUSED;
	}

	/* Non-error responses must be full sized */
	if (rsp_size < exp_size) {
		if (!suppress_logs) {
			warnx("%s: Wrong reply length (%zu bytes)",
			      peer_cmd_prefix(peer, cmd), rsp_size);
			mctp_ctrl_print_response(buf, rsp_size, resp_addr,
						 suppress_logs);
		}
		return -ENOMSG;
	}

	return 0;
}

static int routing_table_entry_len(const struct get_routing_table_entry *entry,
				   size_t available, size_t *entry_len)
{
	if (available < sizeof(*entry))
		return -ENOMSG;

	if (entry->phys_address_size > available - sizeof(*entry))
		return -ENOMSG;

	*entry_len = sizeof(*entry) + entry->phys_address_size;
	return 0;
}

static int mctp_ctrl_validate_get_routing_table_response(
	uint8_t *buf, size_t rsp_size, const char *peer, uint8_t iid,
	struct sockaddr_mctp_ext *resp_addr, bool suppress_logs)
{
	struct mctp_ctrl_resp_get_routing_table *rsp;
	size_t entries_offset =
		offsetof(struct mctp_ctrl_resp_get_routing_table,
			 routing_entries);
	size_t remaining;
	const uint8_t *entry_ptr;
	int rc;

	rc = mctp_ctrl_validate_response(
		buf, rsp_size, entries_offset, peer, iid,
		MCTP_CTRL_CMD_GET_ROUTING_TABLE_ENTRIES, resp_addr,
		suppress_logs);
	if (rc)
		return rc;

	rsp = (void *)buf;
	remaining = rsp_size - entries_offset;
	entry_ptr = rsp->routing_entries;

	for (uint8_t idx = 0; idx < rsp->number_of_entries; idx++) {
		const struct get_routing_table_entry *entry =
			(const struct get_routing_table_entry *)entry_ptr;
		size_t entry_len = 0;

		rc = routing_table_entry_len(entry, remaining, &entry_len);
		if (rc < 0) {
			if (!suppress_logs) {
				warnx("%s: Invalid routing table entry %u length",
				      peer_cmd_prefix(
					      peer,
					      MCTP_CTRL_CMD_GET_ROUTING_TABLE_ENTRIES),
				      idx);
				mctp_ctrl_print_response(buf, rsp_size,
							 resp_addr,
							 suppress_logs);
			}
			return rc;
		}

		entry_ptr += entry_len;
		remaining -= entry_len;
	}

	return 0;
}

static const struct get_routing_table_entry *
routing_table_entry_next(const struct get_routing_table_entry *entry)
{
	return (const struct get_routing_table_entry
			*)((const uint8_t *)entry + sizeof(*entry) +
			   entry->phys_address_size);
}

static void report_transaction_error(struct ctx *ctx, int error_code,
				     uint8_t direction,
				     const struct sockaddr_mctp_ext *req_addr,
				     const void *req, size_t req_len)
{
	struct mctp_error tmperr = { 0 };
	uint8_t local_eid, remote_eid;

	tmperr.error_code = error_code;
	tmperr.direction = direction;

	local_eid = local_addr(ctx, req_addr->smctp_ifindex);
	remote_eid = req_addr->smctp_base.smctp_addr.s_addr;

	/* For error reporting, dest_eid should always be the device that failed.
	 * For RX errors: we sent to remote, waiting for response (remote failed).
	 * For TX errors: we tried to send to remote (remote failed).
	 * In both cases, the remote device is the one with the problem. */
	tmperr.src_eid = local_eid;
	tmperr.dest_eid = remote_eid;

	tmperr.tag = req_addr->smctp_base.smctp_tag;
	tmperr.msg_type = req_addr->smctp_base.smctp_type;

	/* Try to get binding from interface name */
	const char *ifname = NULL;
	int ifindex = req_addr->smctp_ifindex;

	/* If socket doesn't have interface info, try to look up peer by EID */
	if (ifindex == 0 && req_addr->smctp_base.smctp_addr.s_addr != 0) {
		struct peer *peer = find_peer_by_addr(
			ctx, req_addr->smctp_base.smctp_addr.s_addr,
			req_addr->smctp_base.smctp_network);
		if (peer && peer->state == REMOTE) {
			ifindex = peer->phys.ifindex;
		}
	}

	ifname = resolve_ifname(ctx, ifindex);

	if (ifname) {
		const char *binding_str = get_binding_from_ifname(ifname);
		if (strncmp(binding_str, "SMBus", sizeof("SMBus") - 1) == 0)
			tmperr.binding = MCTP_PHYS_BINDING_SMBUS;
		else if (strncmp(binding_str, "USB", sizeof("USB") - 1) == 0)
			tmperr.binding = MCTP_PHYS_BINDING_USB;
		else if (strncmp(binding_str, "I3C", sizeof("I3C") - 1) == 0)
			tmperr.binding = MCTP_PHYS_BINDING_I3C;
		else if (strncmp(binding_str, "SPI", sizeof("SPI") - 1) == 0)
			tmperr.binding = MCTP_PHYS_BINDING_UNSPEC;
	}

	/* Extract command code from request if it's a control message */
	if (req && req_len >= 2 &&
	    req_addr->smctp_base.smctp_type == MCTP_CTRL_HDR_MSG_TYPE) {
		const uint8_t *req_buf = (const uint8_t *)req;
		tmperr.payload[0] = req_buf[0]; /* Instance ID/flags */
		tmperr.payload[1] = req_buf[1]; /* Command code */
		tmperr.payload_len = 2;
	}
	log_mctp_error(ctx, &tmperr, ifname);
}

/* Use endpoint_query_peer() or endpoint_query_phys() instead.
 *
 * resp buffer is allocated, caller to free.
 * Extended addressing is used optionally, depending on ext_addr arg. */
static int endpoint_query_addr(struct ctx *ctx,
			       const struct sockaddr_mctp_ext *req_addr,
			       bool ext_addr, const void *req, size_t req_len,
			       uint8_t **resp, size_t *resp_len,
			       struct sockaddr_mctp_ext *resp_addr,
			       bool suppress_logs)
{
	size_t req_addr_len;
	int sd = -1, val;
	ssize_t rc;
	size_t buf_size;

	uint8_t *buf = NULL;

	*resp = NULL;
	*resp_len = 0;

	sd = mctp_ops.mctp.socket();
	if (sd < 0) {
		if (!suppress_logs)
			warn("socket");
		rc = -errno;
		goto out;
	}

	// We want extended addressing on all received messages
	val = 1;
	rc = mctp_ops.mctp.setsockopt(sd, SOL_MCTP, MCTP_OPT_ADDR_EXT, &val,
				      sizeof(val));
	if (rc < 0) {
		rc = -errno;
		warn("Kernel does not support MCTP extended addressing");
		goto out;
	}

	val = 1;
	rc = mctp_ops.mctp.setsockopt(sd, SOL_MCTP, MCTP_OPT_ENABLE_ERRQUEUE,
				      &val, sizeof(val));
	if (rc < 0) {
		if (ctx->verbose)
			warnx("MCTP error queue not supported by kernel (fd %d)",
			      sd);
	}

	if (ext_addr) {
		req_addr_len = sizeof(struct sockaddr_mctp_ext);
	} else {
		req_addr_len = sizeof(struct sockaddr_mctp);
	}

	if (req_len == 0) {
		bug_warn("zero length request");
		rc = -EPROTO;
		goto out;
	}
	rc = mctp_ops.mctp.sendto(sd, req, req_len, 0,
				  (struct sockaddr *)req_addr, req_addr_len);
	if (rc < 0) {
		rc = -errno;
		if (ctx->verbose && !suppress_logs) {
			warnx("%s: sendto(%s) %zu bytes failed. %s", __func__,
			      ext_addr_tostr(req_addr), req_len, strerror(-rc));
		}
		/* Synthesize a TX error and emit the TransportError signal */
		report_transaction_error(ctx, -rc, MCTP_DIR_TX, req_addr, req,
					 req_len);
		goto out;
	}
	if ((size_t)rc != req_len) {
		bug_warn("incorrect sendto %zd, expected %zu", rc, req_len);
		rc = -EPROTO;
		goto out;
	}

	rc = wait_fd_timeout(sd, EPOLLIN | EPOLLERR, ctx->mctp_timeout);
	if (rc < 0) {
		if (rc == -ETIMEDOUT) {
			report_transaction_error(ctx, ETIMEDOUT, MCTP_DIR_RX,
						 req_addr, req, req_len);
		}
		goto out;
	}
	/* If EPOLLERR was set, check error queue before trying to read */
	if (rc & EPOLLERR) {
		read_mctp_error_queue(ctx, sd, ctx->verbose, req_addr);
		/* If no EPOLLIN, this was purely an error event */
		if (!(rc & EPOLLIN)) {
			rc = -EIO;
			goto out;
		}
	}

	rc = read_message(ctx, sd, &buf, &buf_size, resp_addr, suppress_logs);
	if (rc < 0) {
		goto out;
	}

	if (resp_addr->smctp_base.smctp_type !=
	    req_addr->smctp_base.smctp_type) {
		warnx("Mismatching response type %d for request type %d. dest %s",
		      resp_addr->smctp_base.smctp_type,
		      req_addr->smctp_base.smctp_type,
		      ext_addr_tostr(req_addr));
		rc = -ENOMSG;
	}

	rc = 0;
out:
	close(sd);
	if (rc) {
		free(buf);
	} else {
		*resp = buf;
		*resp_len = buf_size;
	}

	return rc;
}

/* Queries an endpoint peer. Addressing is standard eid/net.
 */
static int endpoint_query_peer(const struct peer *peer, uint8_t req_type,
			       const void *req, size_t req_len, uint8_t **resp,
			       size_t *resp_len,
			       struct sockaddr_mctp_ext *resp_addr)
{
	struct sockaddr_mctp_ext addr = { 0 };

	if (peer->state != REMOTE) {
		bug_warn("%s bad peer %s", __func__, peer_tostr(peer));
		return -EPROTO;
	}

	addr.smctp_base.smctp_family = AF_MCTP;
	addr.smctp_base.smctp_network = peer->net;
	addr.smctp_base.smctp_addr.s_addr = peer->eid;

	addr.smctp_base.smctp_type = req_type;
	addr.smctp_base.smctp_tag = MCTP_TAG_OWNER;

	return endpoint_query_addr(peer->ctx, &addr, false, req, req_len, resp,
				   resp_len, resp_addr, peer->ping_failed_once);
}

/* Queries an endpoint using physical addressing, null EID.
 */
static int endpoint_query_phys(struct ctx *ctx, const dest_phys *dest,
			       uint8_t req_type, const void *req,
			       size_t req_len, uint8_t **resp, size_t *resp_len,
			       struct sockaddr_mctp_ext *resp_addr)
{
	struct sockaddr_mctp_ext addr = { 0 };

	addr.smctp_base.smctp_family = AF_MCTP;
	addr.smctp_base.smctp_network = 0;
	// Physical addressed requests may receive a response where the
	// source-eid that isn't the same as the dest-eid of the request,
	// for example Set Endpoint Id.
	// The kernel mctp stack has special handling for eid=0 to make sure we
	// can recv a response on the socket, so it's important to set eid=0
	// here in the request.
	addr.smctp_base.smctp_addr.s_addr = 0;

	addr.smctp_ifindex = dest->ifindex;
	addr.smctp_halen = dest->hwaddr_len;
	memcpy(addr.smctp_haddr, dest->hwaddr, dest->hwaddr_len);

	addr.smctp_base.smctp_type = req_type;
	addr.smctp_base.smctp_tag = MCTP_TAG_OWNER;

	/* Physical-addressed query: no peer context, never suppress logs. */
	return endpoint_query_addr(ctx, &addr, true, req, req_len, resp,
				   resp_len, resp_addr, false);
}

/* returns -ECONNREFUSED if the endpoint returns failure.
 *
 * Returns new EID (in @new_eidp) and the requested pool size (provided in the
 * Set Endpoint ID reponse, in @req_pool_size) on success.
 */
static int endpoint_send_set_endpoint_id(const struct peer *peer,
					 mctp_eid_t *new_eidp,
					 uint8_t *req_pool_size)
{
	struct sockaddr_mctp_ext addr;
	struct mctp_ctrl_cmd_set_eid req = { 0 };
	struct mctp_ctrl_resp_set_eid *resp = NULL;
	int rc;
	uint8_t *buf = NULL;
	size_t buf_size;
	uint8_t iid, stat, alloc, pool_size = 0;
	const dest_phys *dest = &peer->phys;
	mctp_eid_t new_eid;

	rc = -1;

	iid = mctp_next_iid(peer->ctx);

	mctp_ctrl_msg_hdr_init_req(&req.ctrl_hdr, iid,
				   MCTP_CTRL_CMD_SET_ENDPOINT_ID);

	req.operation =
		mctp_ctrl_cmd_set_eid_set_eid; // TODO: do we want Force?
	req.eid = peer->eid;
	rc = endpoint_query_phys(peer->ctx, dest, MCTP_CTRL_HDR_MSG_TYPE, &req,
				 sizeof(req), &buf, &buf_size, &addr);
	if (rc < 0)
		goto out;

	rc = mctp_ctrl_validate_response(buf, buf_size, sizeof(*resp),
					 dest_phys_tostr(dest), iid,
					 MCTP_CTRL_CMD_SET_ENDPOINT_ID, &addr,
					 peer && peer->ping_failed_once);
	if (rc)
		goto out;

	resp = (void *)buf;

	stat = resp->status >> 4 & 0x3;
	new_eid = resp->eid_set;

	// For both accepted and rejected cases, we learn the new EID of the
	// endpoint. If this is a valid ID, we are likely to be able to handle
	// this, as the caller may be able to change_peer_eid() to the
	// newly-reported eid
	if (stat == 0x01) {
		if (!mctp_eid_is_valid_unicast(new_eid)) {
			warnx("%s rejected assignment eid %d, and reported invalid eid %d",
			      dest_phys_tostr(dest), peer->eid, new_eid);
			rc = -ECONNREFUSED;
			goto out;
		}
	} else if (stat == 0x00) {
		if (!mctp_eid_is_valid_unicast(new_eid)) {
			warnx("%s eid %d replied with invalid eid %d, but 'accepted'",
			      dest_phys_tostr(dest), peer->eid, new_eid);
			rc = -ECONNREFUSED;
			goto out;
		} else if (new_eid != peer->eid) {
			warnx("%s eid %d replied with different eid %d, but 'accepted'",
			      dest_phys_tostr(dest), peer->eid, new_eid);
		}
	} else {
		warnx("%s unexpected status 0x%02x", dest_phys_tostr(dest),
		      resp->status);
	}
	*new_eidp = new_eid;

	alloc = resp->status & 0x3;
	if (alloc != 0) {
		pool_size = resp->eid_pool_size;
		if (peer->ctx->verbose) {
			fprintf(stderr,
				"%s requested allocation of pool size = %d\n",
				dest_phys_tostr(dest), pool_size);
		}
	}

	if (req_pool_size)
		*req_pool_size = pool_size;

	rc = 0;
out:
	free(buf);
	return rc;
}

/* Returns the newly added peer. If @allow_bridged is set, we do not conflict
 * with EIDs that are within bridge pool allocations.
 *
 * Error is -EEXISTS if it exists
 */
static int add_peer(struct ctx *ctx, const dest_phys *dest, mctp_eid_t eid,
		    uint32_t net, struct peer **ret_peer, bool allow_bridged)
{
	struct peer *peer, **tmp;
	struct net *n;

	n = lookup_net(ctx, net);
	if (!n) {
		bug_warn("%s Bad net %u", __func__, net);
		return -EPROTO;
	}

	peer = n->peers[eid];
	if (peer) {
		if (!match_phys(&peer->phys, dest)) {
			return -EEXIST;
		}
		*ret_peer = peer;
		return 0;
	}
	/* In some cases, we want to allow adding a peer that exists within
	 * a bridged range - typically when the peer is behind that bridge.
	 */
	if (!allow_bridged && is_eid_in_bridge_pool(n, ctx, eid, NULL))
		return -EEXIST;

	if (ctx->num_peers == MAX_PEER_SIZE)
		return -ENOMEM;

	// Allocate the peer itself
	peer = calloc(1, sizeof(*peer));
	if (!peer)
		return -ENOMEM;

	// Add it to our peers array
	tmp = realloc(ctx->peers, (ctx->num_peers + 1) * sizeof(*ctx->peers));
	if (!tmp)
		return -ENOMEM;
	ctx->peers = tmp;
	ctx->peers[ctx->num_peers] = peer;
	ctx->num_peers++;

	// Populate it
	peer->eid = eid;
	peer->net = net;
	memcpy(&peer->phys, dest, sizeof(*dest));
	peer->state = REMOTE;
	peer->ctx = ctx;

	// Update network eid map
	n->peers[eid] = peer;

	if (peer->phys.ifindex > 0 && ctx->nl) {
		if (find_local_eid_by_addr(ctx, &peer->phys, peer->net,
					   &peer->local_eid) < 0) {
			warnx("Failed to find local EID for endpoint %s",
			      dest_phys_tostr(dest));
		}
	}

	*ret_peer = peer;
	return 0;
}

static int add_peer_from_addr(struct ctx *ctx,
			      const struct sockaddr_mctp_ext *addr,
			      struct peer **ret_peer)
{
	struct dest_phys phys;

	phys.ifindex = addr->smctp_ifindex;
	memcpy(phys.hwaddr, addr->smctp_haddr, addr->smctp_halen);
	phys.hwaddr_len = addr->smctp_halen;

	return add_peer(ctx, &phys, addr->smctp_base.smctp_addr.s_addr,
			addr->smctp_base.smctp_network, ret_peer, true);
}

/* Stops downstream endpoint polling and removes
 * peer structure when bridge endpoint is being removed.
 */
static int remove_bridged_peers(struct peer *bridge)
{
	mctp_eid_t ep, pool_start, pool_end;
	struct ep_poll_ctx *pctx = NULL;
	struct peer *peer = NULL;
	struct net *n = NULL;
	int rc = 0;
	sd_event_source **sources = bridge->bridge_ep_poll.sources;

	if (bridge->pool_size > 0) {
		pool_end = bridge->pool_start + bridge->pool_size - 1;
		pool_start = bridge->pool_start;
	} else {
		pool_end = eid_alloc_max;
		pool_start = eid_alloc_min;
	}

	n = lookup_net(bridge->ctx, bridge->net);
	if (!n)
		return 0;

	for (ep = pool_start; ep <= pool_end; ep++) {
		if (sources && bridge->pool_size > 0) {
			int idx = ep - pool_start;

			if (idx >= 0 && (unsigned int)idx < bridge->pool_size &&
			    sources[idx]) {
				pctx = sd_event_source_get_userdata(
					sources[idx]);
				rc = sd_event_source_set_enabled(sources[idx],
								 SD_EVENT_OFF);
				if (rc < 0) {
					warnx("Failed to stop polling timer while removing peer %d: %s",
					      ep, strerror(-rc));
				}

				sd_event_source_unref(sources[idx]);
				sources[idx] = NULL;
				free(pctx);
			}
		}

		peer = n->peers[ep];
		if (!peer)
			continue;

		if (peer->pool_owner_eid != bridge->eid)
			continue;

		rc = remove_peer(peer);
		if (rc < 0) {
			warnx("Failed to remove peer %d from bridge eid %d pool [%d - %d]: %s",
			      ep, bridge->eid, pool_start, pool_end,
			      strerror(-rc));
		}
	}

	return 0;
}

static int check_peer_struct(const struct peer *peer, const struct net *n)
{
	if (n->net != peer->net) {
		bug_warn("Mismatching net %d vs peer net %u", n->net,
			 peer->net);
		return -1;
	}

	if (peer != n->peers[peer->eid]) {
		bug_warn("Bad peer: net %u eid %02x", peer->net, peer->eid);
		return -1;
	}

	return 0;
}

static int remove_peer(struct peer *peer)
{
	struct ctx *ctx = NULL;
	struct net *n = NULL;
	struct peer **tmp;
	size_t idx;

	if (!peer) {
		bug_warn("%s: Bad peer, was it removed already?", __func__);
		return -EPROTO;
	}

	ctx = peer->ctx;
	n = lookup_net(peer->ctx, peer->net);
	if (!n) {
		bug_warn("%s: Bad net %u", __func__, peer->net);
		return -EPROTO;
	}

	if (check_peer_struct(peer, n) != 0) {
		bug_warn("%s: Inconsistent state", __func__);
		return -EPROTO;
	}

	unpublish_peer(peer);

	// Clear it
	if (peer->degraded) {
		int rc;

		rc = sd_event_source_set_enabled(peer->recovery.source,
						 SD_EVENT_OFF);
		if (rc < 0) {
			/* XXX: Fix caller assumptions? */
			warnx("Failed to stop recovery timer while removing peer: %d",
			      rc);
		}
		sd_event_source_unref(peer->recovery.source);
	}

	// When removing a direct Bus Owner bridge endpoint, also remove all downstream
	// endpoints managed by that bridge. This prevents recursive calls and ensures
	// proper cleanup of the entire bridge hierarchy when the highest bridge is removed.
	if ((GET_ENDPOINT_TYPE(peer->endpoint_type) == MCTP_BUS_OWNER_BRIDGE) &&
	    peer->is_direct_endpoint) {
		remove_bridged_peers(peer);
		free(peer->bridge_ep_poll.sources);
		peer->bridge_ep_poll.sources = NULL;
	}

	if (peer->bridge_settle_timer) {
		int rc;
		rc = sd_event_source_set_enabled(peer->bridge_settle_timer,
						 SD_EVENT_OFF);
		if (rc < 0) {
			warnx("Failed to stop bridge settle timer while removing peer: %d",
			      rc);
		}
		sd_event_source_unref(peer->bridge_settle_timer);
		peer->bridge_settle_timer = NULL;
	}

	n->peers[peer->eid] = NULL;
	free(peer->message_types);
	free(peer->ignore_message_types);
	free(peer->uuid);
	free(peer->ignore_eids);
	free(peer->routing_table_entry);
	free(peer->static_pool_eids);

	for (idx = 0; idx < ctx->num_peers; idx++) {
		if (ctx->peers[idx] == peer)
			break;
	}

	if (idx == ctx->num_peers) {
		bug_warn("peer net %u, eid %d not found on remove!", peer->net,
			 peer->eid);
		return -EPROTO;
	}

	// remove from peers array & resize
	ctx->num_peers--;
	memmove(ctx->peers + idx, ctx->peers + idx + 1,
		(ctx->num_peers - idx) * sizeof(struct peer *));

	if (ctx->num_peers > 0) {
		tmp = realloc(ctx->peers,
			      ctx->num_peers * sizeof(struct peer *));
		if (!tmp) {
			warn("%s: peer realloc(reduce!) failed", __func__);
			// we'll re-try on next add/remove
		} else {
			ctx->peers = tmp;
		}
	} else {
		free(ctx->peers);
		ctx->peers = NULL;
	}

	free(peer);

	return 0;
}

static void free_peers(struct ctx *ctx)
{
	for (size_t i = 0; i < ctx->num_peers; i++) {
		struct peer *peer = ctx->peers[i];
		free(peer->message_types);
		free(peer->ignore_message_types);
		free(peer->uuid);
		free(peer->path);
		free(peer->ignore_eids);
		free(peer->routing_table_entry);
		free(peer->static_pool_eids);
		free(peer->bridge_ep_poll.sources);
		sd_bus_slot_unref(peer->slot_obmc_endpoint);
		sd_bus_slot_unref(peer->slot_cc_endpoint);
		sd_bus_slot_unref(peer->slot_bridge);
		sd_bus_slot_unref(peer->slot_uuid);
		sd_bus_slot_unref(peer->slot_binding_endpoint);
		free(peer);
	}

	free(ctx->peers);
}

/* Returns -EEXIST if the new_eid is already used */
static int change_peer_eid(struct peer *peer, mctp_eid_t new_eid)
{
	struct net *n = NULL;
	int rc;

	if (!mctp_eid_is_valid_unicast(new_eid))
		return -EINVAL;

	n = lookup_net(peer->ctx, peer->net);
	if (!n) {
		bug_warn("%s: Bad net %u", __func__, peer->net);
		return -EPROTO;
	}

	if (check_peer_struct(peer, n) != 0) {
		bug_warn("%s: Inconsistent state", __func__);
		return -EPROTO;
	}

	if (n->peers[new_eid])
		return -EEXIST;

	/* publish & unpublish will update peer->path */
	unpublish_peer(peer);
	n->peers[new_eid] = n->peers[peer->eid];
	n->peers[peer->eid] = NULL;
	peer->eid = new_eid;
	rc = publish_peer(peer, true);
	if (rc)
		return rc;

	return 0;
}

static int peer_set_mtu(struct ctx *ctx, struct peer *peer, uint32_t mtu)
{
	int rc;

	if (!mctp_nl_if_exists(peer->ctx->nl, peer->phys.ifindex)) {
		bug_warn("%s: no interface for ifindex %d", __func__,
			 peer->phys.ifindex);
		return -EPROTO;
	}

	rc = mctp_nl_route_del(ctx->nl, peer->eid, 0, peer->phys.ifindex, NULL);
	if (rc < 0 && rc != -ENOENT) {
		warnx("%s, Failed removing existing route for eid %d %s",
		      __func__, peer->phys.ifindex,
		      mctp_nl_if_byindex(ctx->nl, peer->phys.ifindex));
		// Continue regardless, route_add will likely fail with EEXIST
	}

	rc = mctp_nl_route_add(ctx->nl, peer->eid, 0, peer->phys.ifindex, NULL,
			       mtu);
	if (rc >= 0) {
		peer->mtu = mtu;
	}
	return rc;
}

struct eid_allocation {
	mctp_eid_t start;
	unsigned int extent; /* 0 = only the start EID */
};

/* Allocate an unused dynamic EID for a peer, optionally with an associated
 * bridge range (of size @bridged_len).
 *
 * We try to find the first allocation that contains the base EID plus the
 * full range. If no space for that exists, we return the largest
 * possible range. If the requested range is 0, then the first available
 * (single) EID will suit as a match, the returned alloc->extent will be zero.
 *
 * It is up to the caller to check whether this range is suitable, and
 * actually reserve that EID (& range) if so.
 *
 * returns 0 on success (with @alloc populated), non-zero on failure.
 */
static int allocate_eid(struct ctx *ctx, struct net *net,
			unsigned int bridged_len, struct eid_allocation *alloc)
{
	struct eid_allocation cur = { 0 }, best = { 0 };
	mctp_eid_t eid;

	for (eid = ctx->dyn_eid_min; eid <= ctx->dyn_eid_max; eid++) {
		if (net->peers[eid]) {
			// reset our current candidate allocation
			cur.start = 0;
			eid += net->peers[eid]->pool_size;
			continue;
		}

		// start a new candidate allocation
		if (!cur.start)
			cur.start = eid;
		cur.extent = eid - cur.start;

		// if this suits, we're done
		if (cur.extent == bridged_len) {
			*alloc = cur;
			return 0;
		}

		if (cur.extent > best.extent || !best.start)
			best = cur;
	}

	if (best.start) {
		*alloc = best;
		return 0;
	}

	return -1;
}

static int endpoint_assign_eid(struct ctx *ctx, sd_bus_error *berr,
			       const dest_phys *dest, struct peer **ret_peer,
			       mctp_eid_t static_eid,
			       const uint8_t *ignore_message_types,
			       size_t ignore_message_types_len,
			       bool assign_bridge)
{
	mctp_eid_t new_eid;
	struct net *n = NULL;
	struct peer *peer = NULL;
	uint8_t req_pool_size;
	uint32_t net;
	int rc;

	net = mctp_nl_net_byindex(ctx->nl, dest->ifindex);
	if (!net) {
		bug_warn("No net known for ifindex %d", dest->ifindex);
		return -EPROTO;
	}

	n = lookup_net(ctx, net);
	if (!n) {
		bug_warn("Unknown net %d", net);
		return -EPROTO;
	}

	if (static_eid) {
		rc = add_peer(ctx, dest, static_eid, net, &peer, false);
		if (rc < 0)
			return rc;

		new_eid = static_eid;
	} else {
		struct eid_allocation alloc;
		unsigned int alloc_size = 0;

		if (assign_bridge)
			alloc_size = ctx->max_pool_size;

		rc = allocate_eid(ctx, n, alloc_size, &alloc);
		if (rc) {
			warnx("Cannot allocate any EID (+pool %d) on net %d for %s",
			      alloc_size, net, dest_phys_tostr(dest));
			sd_bus_error_setf(berr, SD_BUS_ERROR_FAILED,
					  "Ran out of EIDs");
			return -EADDRNOTAVAIL;
		}

		new_eid = alloc.start;

		rc = add_peer(ctx, dest, new_eid, net, &peer, false);
		if (rc < 0)
			return rc;

		peer->pool_size = alloc.extent;
		if (peer->pool_size)
			peer->pool_start = new_eid + 1;
	}

	rc = endpoint_send_set_endpoint_id(peer, &new_eid, &req_pool_size);
	if (rc == -ECONNREFUSED)
		sd_bus_error_setf(
			berr, SD_BUS_ERROR_FAILED,
			"Endpoint returned failure to Set Endpoint ID");

	if (rc < 0) {
		// we have not yet created the pool route, reset here so that
		// remove_peer() does not attempt to remove it
		peer->pool_size = 0;
		peer->pool_start = 0;
		remove_peer(peer);
		return rc;
	}

	// Success! We contacted the device.
	warnx("Successfully discovered and setup endpoint EID %d", new_eid);
	if ((req_pool_size > peer->pool_size) && !static_eid) {
		warnx("EID %d: requested pool size (%d) > pool size available (%d), limiting.",
		      peer->eid, req_pool_size, peer->pool_size);
	} else {
		// peer will likely have requested less than the available range
		peer->pool_size = req_pool_size;
	}

	if (!peer->pool_size)
		peer->pool_start = 0;

	if (new_eid != peer->eid) {
		// avoid allocation for any different EID in response
		warnx("Mismatch of requested from received EID, resetting the pool");
		peer->pool_size = 0;
		peer->pool_start = 0;
		rc = change_peer_eid(peer, new_eid);
		if (rc == -EEXIST) {
			sd_bus_error_setf(
				berr, SD_BUS_ERROR_FAILED,
				"Endpoint requested EID %d instead of assigned %d, already used",
				new_eid, peer->eid);
		}
		if (rc < 0) {
			remove_peer(peer);
			return rc;
		}
	}

	if (ignore_message_types_len > 0) {
		peer->ignore_message_types = malloc(ignore_message_types_len);
		if (!peer->ignore_message_types) {
			rc = -ENOMEM;
			return rc;
		}
		memcpy(peer->ignore_message_types, ignore_message_types,
		       ignore_message_types_len);
		peer->num_ignore_message_types = ignore_message_types_len;
	} else {
		peer->ignore_message_types = NULL;
		peer->num_ignore_message_types = 0;
	}

	rc = setup_added_peer(peer);
	if (rc < 0)
		return rc;

	// Set service state to Enabled for non-bridge endpoints after discovery completion
	if (peer->pool_size == 0) {
		struct link *link =
			mctp_nl_get_link_userdata(ctx->nl, dest->ifindex);
		if (link && link->service_state == SERVICE_STATE_STARTING) {
			link->service_state = SERVICE_STATE_ENABLED;
			rc = sd_bus_emit_properties_changed(
				ctx->bus, link->path,
				OPENBMC_SERVICE_READINESS_IFACE, "State", NULL);
			if (rc < 0) {
				warnx("%s: Service state change emit failed: %d %s",
				      __func__, rc, strerror(-rc));
			}
		}
	}

	*ret_peer = peer;

	return 0;
}

/* Populates a sd_bus_error based on mctpd's convention for error codes.
 * Does nothing if berr is already set.
 */
static void set_berr(struct ctx *ctx, int errcode, sd_bus_error *berr)
{
	bool existing = false;

	if (sd_bus_error_is_set(berr)) {
		existing = true;
	} else
		switch (errcode) {
		case -ETIMEDOUT:
			sd_bus_error_setf(berr, SD_BUS_ERROR_TIMEOUT,
					  "MCTP Endpoint did not respond");
			break;
		case -ECONNREFUSED:
			// MCTP_CTRL_CC_ERROR or others
			sd_bus_error_setf(berr, SD_BUS_ERROR_FAILED,
					  "MCTP Endpoint replied with failure");
			break;
		case -EBUSY:
			// MCTP_CTRL_CC_ERROR_NOT_READY
			sd_bus_error_setf(berr, SD_BUS_ERROR_FAILED,
					  "MCTP Endpoint busy");
			break;
		case -ENOTSUP:
			// MCTP_CTRL_CC_ERROR_UNSUPPORTED_CMD
			sd_bus_error_setf(berr, SD_BUS_ERROR_FAILED,
					  "Endpoint replied 'unsupported'");
			break;
		case -EPROTO:
			// BUG
			sd_bus_error_setf(berr, SD_BUS_ERROR_FAILED,
					  "Internal error");
			break;
		default:
			if (errcode < 0)
				sd_bus_error_setf(berr, SD_BUS_ERROR_FAILED,
						  "Request failed");
			break;
		}
}

static int query_get_endpoint_id(struct ctx *ctx, const dest_phys *dest,
				 mctp_eid_t *ret_eid, uint8_t *ret_ep_type,
				 uint8_t *ret_media_spec, struct peer *peer)
{
	struct sockaddr_mctp_ext addr;
	struct mctp_ctrl_cmd_get_eid req = { 0 };
	struct mctp_ctrl_resp_get_eid *resp = NULL;
	uint8_t *buf = NULL;
	size_t buf_size;
	uint8_t iid;
	int rc;

	iid = mctp_next_iid(ctx);

	mctp_ctrl_msg_hdr_init_req(&req.ctrl_hdr, iid,
				   MCTP_CTRL_CMD_GET_ENDPOINT_ID);

	if (peer)
		rc = endpoint_query_peer(peer, MCTP_CTRL_HDR_MSG_TYPE, &req,
					 sizeof(req), &buf, &buf_size, &addr);
	else
		rc = endpoint_query_phys(ctx, dest, MCTP_CTRL_HDR_MSG_TYPE,
					 &req, sizeof(req), &buf, &buf_size,
					 &addr);
	if (rc < 0)
		goto out;

	rc = mctp_ctrl_validate_response(buf, buf_size, sizeof(*resp),
					 dest_phys_tostr(dest), iid,
					 MCTP_CTRL_CMD_GET_ENDPOINT_ID, &addr,
					 peer && peer->ping_failed_once);
	if (rc)
		goto out;

	resp = (void *)buf;

	*ret_eid = resp->eid;
	*ret_ep_type = resp->eid_type;
	*ret_media_spec = resp->medium_data;
out:
	free(buf);
	return rc;
}

/* Returns 0, and ret_peer associated with the endpoint.
 * Returns 0, ret_peer=NULL if the endpoint successfully replies "not yet assigned".
 * Returns negative error code on failure.
 */
static int get_endpoint_peer(struct ctx *ctx, sd_bus_error *berr,
			     const dest_phys *dest, struct peer **ret_peer,
			     mctp_eid_t *ret_cur_eid)
{
	mctp_eid_t eid;
	uint8_t ep_type, medium_spec;
	struct peer *peer = NULL;
	uint32_t net;
	int rc;

	*ret_peer = NULL;
	rc = query_get_endpoint_id(ctx, dest, &eid, &ep_type, &medium_spec,
				   /*peer=*/NULL);
	if (rc)
		return rc;

	if (ret_cur_eid)
		*ret_cur_eid = eid;

	net = mctp_nl_net_byindex(ctx->nl, dest->ifindex);
	if (!net) {
		return -EPROTO;
	}

	peer = find_peer_by_phys(ctx, dest);
	if (peer) {
		/* Existing entry */
		if (eid == 0) {
			// EID not yet assigned
			remove_peer(peer);
			return 0;
		} else if (peer->eid != eid) {
			rc = change_peer_eid(peer, eid);
			/* Conflict while changing EIDs: the new EID already
			 * exists in our local table. We can only delete the
			 * entry because it's no longer valid, and the caller
			 * will handle the error */
			if (rc < 0) {
				remove_peer(peer);
				return rc;
			}
		}
	} else {
		if (eid == 0) {
			// Not yet assigned.
			return 0;
		}
		/* New endpoint */
		rc = add_peer(ctx, dest, eid, net, &peer, false);
		if (rc < 0)
			return rc;
	}

	peer->endpoint_type = ep_type;
	peer->medium_spec = medium_spec;
	rc = setup_added_peer(peer);
	if (rc < 0)
		return rc;

	*ret_peer = peer;
	return 0;
}

static int query_get_peer_msgtypes(struct peer *peer)
{
	struct sockaddr_mctp_ext addr;
	struct mctp_ctrl_cmd_get_msg_type_support req;
	struct mctp_ctrl_resp_get_msg_type_support *resp = NULL;
	uint8_t *new_message_types = NULL;
	uint8_t *buf = NULL;
	size_t buf_size, expect_size;
	uint8_t iid;
	int rc;

	iid = mctp_next_iid(peer->ctx);

	mctp_ctrl_msg_hdr_init_req(&req.ctrl_hdr, iid,
				   MCTP_CTRL_CMD_GET_MESSAGE_TYPE_SUPPORT);

	rc = endpoint_query_peer(peer, MCTP_CTRL_HDR_MSG_TYPE, &req,
				 sizeof(req), &buf, &buf_size, &addr);
	if (rc < 0)
		goto out;

	rc = mctp_ctrl_validate_response(buf, buf_size, sizeof(*resp),
					 peer_tostr_short(peer), iid,
					 MCTP_CTRL_CMD_GET_MESSAGE_TYPE_SUPPORT,
					 &addr, peer->ping_failed_once);
	if (rc)
		goto out;

	resp = (void *)buf;
	expect_size = sizeof(*resp) + resp->msg_type_count;
	if (buf_size != expect_size) {
		warnx("%s: bad reply length. got %zu, expected %zu, %d entries. dest %s",
		      __func__, buf_size, expect_size, resp->msg_type_count,
		      peer_tostr(peer));
		rc = -ENOMSG;
		goto out;
	}

	new_message_types = malloc(resp->msg_type_count);
	if (!new_message_types) {
		rc = -ENOMEM;
		goto out;
	}

	// free previous message types to avoid memory leak
	free(peer->message_types);
	peer->message_types = new_message_types;
	peer->num_message_types = 0;

	size_t idx = 0;
	bool ignore = false;
	uint8_t count_ignore = 0;
	for (size_t resp_i = 0; resp_i < resp->msg_type_count; resp_i++) {
		ignore = false;
		for (size_t k = 0; k < peer->num_ignore_message_types; k++) {
			if (peer->ignore_message_types[k] ==
			    ((uint8_t *)(resp + 1))[resp_i]) {
				ignore = true;
				count_ignore++;
				break;
			}
		}
		if (!ignore) {
			peer->message_types[idx++] =
				((uint8_t *)(resp + 1))[resp_i];
		}
	}
	peer->num_message_types = resp->msg_type_count - count_ignore;
	rc = 0;
out:
	free(buf);
	return rc;
}

static int peer_set_uuid(struct peer *peer, const uint8_t uuid[16])
{
	if (!peer->uuid) {
		peer->uuid = malloc(16);
		if (!peer->uuid)
			return -ENOMEM;
	}
	memcpy(peer->uuid, uuid, 16);
	return 0;
}

static int query_get_peer_uuid_by_phys(struct ctx *ctx, const dest_phys *dest,
				       uint8_t uuid[16])
{
	struct sockaddr_mctp_ext addr;
	struct mctp_ctrl_cmd_get_uuid req;
	struct mctp_ctrl_resp_get_uuid *resp = NULL;
	uint8_t *buf = NULL;
	size_t buf_size;
	uint8_t iid;
	int rc;

	iid = mctp_next_iid(ctx);

	mctp_ctrl_msg_hdr_init_req(&req.ctrl_hdr, iid,
				   MCTP_CTRL_CMD_GET_ENDPOINT_UUID);

	rc = endpoint_query_phys(ctx, dest, MCTP_CTRL_HDR_MSG_TYPE, &req,
				 sizeof(req), &buf, &buf_size, &addr);
	if (rc < 0)
		goto out;

	/* Physical-addressed query without peer context; never suppress. */
	rc = mctp_ctrl_validate_response(buf, buf_size, sizeof(*resp),
					 dest_phys_tostr(dest), iid,
					 MCTP_CTRL_CMD_GET_ENDPOINT_UUID, &addr,
					 false);
	if (rc)
		goto out;

	resp = (void *)buf;
	memcpy(uuid, resp->uuid, 16);

out:
	free(buf);
	return rc;
}

static int query_get_peer_uuid(struct peer *peer, uint8_t uuid_out[16])
{
	struct sockaddr_mctp_ext addr;
	struct mctp_ctrl_cmd_get_uuid req;
	struct mctp_ctrl_resp_get_uuid *resp = NULL;
	uint8_t *buf = NULL;
	size_t buf_size;
	uint8_t iid;
	int rc;

	if (peer->state != REMOTE) {
		warnx("%s: Wrong state for peer %s", __func__,
		      peer_tostr(peer));
		return -EPROTO;
	}

	iid = mctp_next_iid(peer->ctx);

	mctp_ctrl_msg_hdr_init_req(&req.ctrl_hdr, iid,
				   MCTP_CTRL_CMD_GET_ENDPOINT_UUID);

	rc = endpoint_query_peer(peer, MCTP_CTRL_HDR_MSG_TYPE, &req,
				 sizeof(req), &buf, &buf_size, &addr);
	if (rc < 0)
		goto out;

	rc = mctp_ctrl_validate_response(buf, buf_size, sizeof(*resp),
					 peer_tostr_short(peer), iid,
					 MCTP_CTRL_CMD_GET_ENDPOINT_UUID, &addr,
					 peer->ping_failed_once);
	if (rc)
		goto out;

	resp = (void *)buf;
	memcpy(uuid_out, resp->uuid, 16);
	rc = 0;

out:
	free(buf);
	return rc;
}

static int validate_dest_phys(struct ctx *ctx, const dest_phys *dest)
{
	if (dest->hwaddr_len > MAX_ADDR_LEN) {
		warnx("bad hwaddr_len %zu", dest->hwaddr_len);
		return -EINVAL;
	}
	if (dest->ifindex <= 0) {
		warnx("bad ifindex %d", dest->ifindex);
		return -EINVAL;
	}
	if (!mctp_nl_net_byindex(ctx->nl, dest->ifindex)) {
		warnx("unknown ifindex %d", dest->ifindex);
		return -EINVAL;
	}
	return 0;
}

static int message_read_hwaddr(sd_bus_message *call, dest_phys *dest)
{
	int rc;
	const void *msg_hwaddr = NULL;
	size_t msg_hwaddr_len;

	rc = sd_bus_message_read_array(call, 'y', &msg_hwaddr, &msg_hwaddr_len);
	if (rc < 0)
		return rc;
	if (msg_hwaddr_len > MAX_ADDR_LEN)
		return -EINVAL;

	memset(dest->hwaddr, 0x0, MAX_ADDR_LEN);
	memcpy(dest->hwaddr, msg_hwaddr, msg_hwaddr_len);
	dest->hwaddr_len = msg_hwaddr_len;
	return 0;
}

/* SetupEndpoint method tries the following in order:
  - request Get Endpoint ID to add to the known table, return that
  - request Set Endpoint ID, return that */
static int method_setup_endpoint(sd_bus_message *call, void *data,
				 sd_bus_error *berr)
{
	dest_phys desti = { 0 }, *dest = &desti;
	uint8_t ep_type, medium_spec;
	const char *peer_path = NULL;
	struct link *link = data;
	struct ctx *ctx = link->ctx;
	struct peer *peer = NULL;
	bool new = true;
	mctp_eid_t eid;
	uint32_t net;
	int rc;

	dest->ifindex = link->ifindex;
	if (dest->ifindex <= 0)
		return sd_bus_error_setf(berr, SD_BUS_ERROR_INVALID_ARGS,
					 "Unknown MCTP interface");

	rc = message_read_hwaddr(call, dest);
	if (rc < 0)
		goto err;

	rc = validate_dest_phys(ctx, dest);
	if (rc < 0)
		return sd_bus_error_setf(berr, SD_BUS_ERROR_INVALID_ARGS,
					 "Bad physaddr");

	net = mctp_nl_net_byindex(ctx->nl, dest->ifindex);
	if (!net) {
		rc = -EINVAL;
		goto err;
	}

	/* Get Endpoint ID */
	rc = query_get_endpoint_id(ctx, dest, &eid, &ep_type, &medium_spec,
				   /*peer=*/NULL);
	if (rc)
		goto err;

	/* does it exist already? */
	peer = find_peer_by_phys(ctx, dest);

	/* we have a few cases:
	 *
	 * - no peer, no eid
	 *    --> set up both
	 * - no peer, eid, not a bridge:
	 *    --> create a peer with the given EID
	 * - no peer, eid, bridge:
	 *    --> reassign, including bridge
	 * - peer, eid (but not matching)
	 *    --> change EID if possible, or reassign
	 * - peer, no eid:
	 *    --> remove peer, reassign
	 */

	bool is_bridge = GET_MCTP_GET_EID_EP_TYPE(ep_type) ==
			 MCTP_GET_EID_EP_TYPE_BRIDGE;

	printf("%s: peer %p, eid %d, is_bridge %d ep type %x\n", __func__, peer,
	       eid, is_bridge, ep_type);

	if (peer) {
		/* TODO: we could check the bridge allocation through the
		 * Get Allocation Information op of Allocate Endpoint IDs,
		 * and be slightly more accurate with persisting the EID...
		 */
		if (eid && peer->eid == eid && is_bridge == !!peer->pool_size) {
			/* all matching: no action required */
			new = false;
			goto out;
		}
		/* we have some difference in EID / bridge config, remove and
		 * reassign */
		remove_peer(peer);
		peer = NULL;
	}

	/* simple allocation: try to use existing EID */
	if (eid && !is_bridge) {
		rc = add_peer(ctx, dest, eid, net, &peer, false);
		if (rc == -EEXIST) {
			/* proposed EID already present on a different peer,
			 * fall back to assigning */
		} else if (rc < 0) {
			goto err;
		} else {
			peer->endpoint_type = ep_type;
			peer->medium_spec = medium_spec;
			rc = setup_added_peer(peer);
			if (rc)
				goto err;
			goto out;
		}
	}

	rc = endpoint_assign_eid(ctx, berr, dest, &peer, 0, NULL, 0, true);
	if (rc < 0)
		goto err;

	peer->is_direct_endpoint = true;
	if (peer->pool_size)
		endpoint_allocate_eids(peer);

out:
	peer_path = path_from_peer(peer);
	if (!peer_path) {
		rc = -EPROTO;
		goto err;
	}
	return sd_bus_reply_method_return(call, "yisb", peer->eid, peer->net,
					  peer_path, new);

err:
	set_berr(ctx, rc, berr);
	return rc;
}

static int method_assign_endpoint(sd_bus_message *call, void *data,
				  sd_bus_error *berr)
{
	dest_phys desti, *dest = &desti;
	const char *peer_path = NULL;
	struct link *link = data;
	struct ctx *ctx = link->ctx;
	struct peer *peer = NULL;
	int rc;

	dest->ifindex = link->ifindex;
	if (dest->ifindex <= 0)
		return sd_bus_error_setf(berr, SD_BUS_ERROR_INVALID_ARGS,
					 "Unknown MCTP interface");

	rc = message_read_hwaddr(call, dest);
	if (rc < 0)
		goto err;

	rc = validate_dest_phys(ctx, dest);
	if (rc < 0)
		return sd_bus_error_setf(berr, SD_BUS_ERROR_INVALID_ARGS,
					 "Bad physaddr");

	peer = find_peer_by_phys(ctx, dest);
	if (peer) {
		// Return existing record.
		peer_path = path_from_peer(peer);
		if (!peer_path)
			goto err;

		return sd_bus_reply_method_return(call, "yisb", peer->eid,
						  peer->net, peer_path, 0);
	}

	rc = endpoint_assign_eid(ctx, berr, dest, &peer, 0, NULL, 0, true);
	if (rc < 0)
		goto err;

	peer->is_direct_endpoint = true;
	peer_path = path_from_peer(peer);
	if (!peer_path)
		goto err;

	/* MCTP Bridge Support */
	/* Look for starting pool EID
	 * Allocate Endopint EID
	 * Update pool endpoints to dbus */

	if (peer->pool_size > 0) {
		/* new start eid will be assigned before MCTP Allocate eid control command */
		peer->pool_start = peer->eid + 1;
		rc = endpoint_allocate_eids(peer);
	} else if (peer->pool_size == 0 &&
		   GET_ENDPOINT_TYPE(peer->endpoint_type) ==
			   MCTP_BUS_OWNER_BRIDGE) {
		// TODO: Do we need bridge timer here?
		peer->pool_size = 0;
		peer->pool_start = 0;
		peer->static_pool_eids =
			malloc((eid_alloc_max + 1) * sizeof(mctp_eid_t));
		memset(peer->static_pool_eids, 0,
		       (eid_alloc_max + 1) * sizeof(mctp_eid_t));
		sd_bus_add_object_vtable(peer->ctx->bus, &peer->slot_bridge,
					 peer->path, CC_MCTP_DBUS_IFACE_BRIDGE,
					 bus_endpoint_bridge, peer);

		rc = sd_bus_emit_interfaces_added(peer->ctx->bus, peer->path,
						  CC_MCTP_DBUS_IFACE_BRIDGE,
						  NULL);
		if (rc < 0) {
			warnx("Failed to emit add %s signal for endpoint %d : %s",
			      CC_MCTP_DBUS_IFACE_BRIDGE, peer->eid,
			      strerror(-rc));
		}
		rc = query_routing_table(peer);
		if (rc < 0)
			goto err;
	}

	return sd_bus_reply_method_return(call, "yisb", peer->eid, peer->net,
					  peer_path, 1);
err:
	set_berr(ctx, rc, berr);
	return rc;
}

static int method_assign_endpoint_static(sd_bus_message *call, void *data,
					 sd_bus_error *berr)
{
	dest_phys desti, *dest = &desti;
	const char *peer_path = NULL;
	struct peer *peer = NULL;
	struct link *link = data;
	struct ctx *ctx = link->ctx;
	uint8_t eid, start_eid;
	const uint8_t *ignore_eids = NULL;
	size_t ignore_eids_len;
	const uint8_t *ignore_message_types = NULL;
	size_t ignore_message_types_len;
	int rc;

	dest->ifindex = link->ifindex;
	if (dest->ifindex <= 0)
		return sd_bus_error_setf(berr, SD_BUS_ERROR_INVALID_ARGS,
					 "Unknown MCTP interface");

	rc = message_read_hwaddr(call, dest);
	if (rc < 0)
		goto err;

	rc = sd_bus_message_read(call, "y", &eid);
	if (rc < 0)
		goto err;

	rc = sd_bus_message_read(call, "y", &start_eid);
	if (rc < 0)
		goto err;

	rc = sd_bus_message_read_array(call, 'y', (const void **)&ignore_eids,
				       &ignore_eids_len);
	if (rc < 0)
		goto err;

	rc = sd_bus_message_read_array(call, 'y',
				       (const void **)&ignore_message_types,
				       &ignore_message_types_len);
	if (rc < 0)
		goto err;

	rc = validate_dest_phys(ctx, dest);
	if (rc < 0)
		return sd_bus_error_setf(berr, SD_BUS_ERROR_INVALID_ARGS,
					 "Bad physaddr");

	peer = find_peer_by_phys(ctx, dest);
	if (peer) {
		if (peer->eid != eid) {
			return sd_bus_error_setf(
				berr, SD_BUS_ERROR_INVALID_ARGS,
				"Already assigned a different EID");
		}

		// Return existing record.
		peer_path = path_from_peer(peer);
		if (!peer_path)
			goto err;

		return sd_bus_reply_method_return(call, "yisb", peer->eid,
						  peer->net, peer_path, 0);
	} else {
		uint32_t netid;

		// is the requested EID already in use? if so, reject
		netid = mctp_nl_net_byindex(ctx->nl, dest->ifindex);
		peer = find_peer_by_addr(ctx, eid, netid);
		if (peer) {
			return sd_bus_error_setf(berr,
						 SD_BUS_ERROR_INVALID_ARGS,
						 "Address in use");
		}
	}

	rc = endpoint_assign_eid(ctx, berr, dest, &peer, eid,
				 ignore_message_types, ignore_message_types_len,
				 false);
	if (rc < 0) {
		goto err;
	}

	// Store ignore EIDs if provided
	if (ignore_eids_len > 0) {
		peer->ignore_eids = malloc(ignore_eids_len);
		if (!peer->ignore_eids) {
			rc = -ENOMEM;
			goto err;
		}
		memcpy(peer->ignore_eids, ignore_eids, ignore_eids_len);
		peer->num_ignore_eids = ignore_eids_len;
	} else {
		peer->ignore_eids = NULL;
		peer->num_ignore_eids = 0;
	}

	peer->is_direct_endpoint = true;
	peer_path = path_from_peer(peer);
	if (!peer_path)
		goto err;

	/* MCTP Bridge Support */
	/* Allocate Endopint EID
	 * Update pool endpoints to dbus
	 * Get Routing Table Data
	 * Deprecate non-active eid*/
	if (peer->pool_size > 0) {
		peer->pool_start = start_eid;
		rc = endpoint_allocate_eids(peer);
	} else if (GET_ENDPOINT_TYPE(peer->endpoint_type) ==
		   MCTP_BUS_OWNER_BRIDGE) {
		// TODO: Do we need bridge timer here?
		peer->pool_size = 0;
		peer->pool_start = 0;
		peer->static_pool_eids =
			malloc((eid_alloc_max + 1) * sizeof(mctp_eid_t));
		memset(peer->static_pool_eids, 0,
		       (eid_alloc_max + 1) * sizeof(mctp_eid_t));
		sd_bus_add_object_vtable(peer->ctx->bus, &peer->slot_bridge,
					 peer->path, CC_MCTP_DBUS_IFACE_BRIDGE,
					 bus_endpoint_bridge, peer);

		rc = sd_bus_emit_interfaces_added(peer->ctx->bus, peer->path,
						  CC_MCTP_DBUS_IFACE_BRIDGE,
						  NULL);
		if (rc < 0) {
			warnx("Failed to emit add %s signal for endpoint %d : %s",
			      CC_MCTP_DBUS_IFACE_BRIDGE, peer->eid,
			      strerror(-rc));
		}
		rc = query_routing_table(peer);
		if (rc < 0)
			goto err;
	}

	return sd_bus_reply_method_return(call, "yisb", peer->eid, peer->net,
					  peer_path, 1);
err:
	set_berr(ctx, rc, berr);
	return rc;
}

static int method_learn_endpoint(sd_bus_message *call, void *data,
				 sd_bus_error *berr)
{
	int rc;
	const char *peer_path = NULL;
	dest_phys desti, *dest = &desti;
	struct link *link = data;
	struct ctx *ctx = link->ctx;
	struct peer *peer = NULL;
	mctp_eid_t eid = 0;

	dest->ifindex = link->ifindex;
	if (dest->ifindex <= 0)
		return sd_bus_error_setf(berr, SD_BUS_ERROR_INVALID_ARGS,
					 "Unknown MCTP interface");

	rc = message_read_hwaddr(call, dest);
	if (rc < 0)
		goto err;

	rc = validate_dest_phys(ctx, dest);
	if (rc < 0)
		return sd_bus_error_setf(berr, SD_BUS_ERROR_INVALID_ARGS,
					 "Bad physaddr");

	rc = get_endpoint_peer(ctx, berr, dest, &peer, &eid);
	if (rc == -EEXIST) {
		/* We have a conflict with an existing endpoint, so can't
		 * learn; recovery would requre a Set Endpoint ID. */
		return sd_bus_error_setf(
			berr, SD_BUS_ERROR_FILE_EXISTS,
			"Endpoint claimed EID %d which is already used", eid);
	}
	if (rc < 0)
		goto err;
	if (!peer)
		return sd_bus_reply_method_return(call, "yisb", 0, 0, "", 0);

	uint8_t ep_type = GET_MCTP_GET_EID_EP_TYPE(peer->endpoint_type);
	if (ep_type == MCTP_GET_EID_EP_TYPE_BRIDGE) {
		warnx("LearnEndpoint, eid %d: Get EID response "
		      "indicated a bridge with existing EID, "
		      "but no pool is assignable",
		      peer->eid);
	}

	peer_path = path_from_peer(peer);
	peer->is_direct_endpoint = true;

	if (!peer_path)
		goto err;
	return sd_bus_reply_method_return(call, "yisb", peer->eid, peer->net,
					  peer_path, 1);
err:
	set_berr(ctx, rc, berr);
	return rc;
}

/* Async EndpointPing: state for a ping in flight */
struct pending_ping {
	sd_bus_message *call; /* held D-Bus method call for deferred reply */
	sd_event_source *io_source; /* event source for socket readability */
	sd_event_source *tm_source; /* event source for timeout */
	struct peer *peer;
	struct ctx *ctx;
	int sock_fd;
	bool is_dummy; /* true if peer was created just for this ping */
	mctp_eid_t eid;
	struct sockaddr_mctp_ext req_addr; /* saved for error reporting */
};

static void cleanup_pending_ping(struct pending_ping *pp)
{
	if (!pp)
		return;

	if (pp->io_source) {
		sd_event_source_disable_unref(pp->io_source);
		pp->io_source = NULL;
	}
	if (pp->tm_source) {
		sd_event_source_disable_unref(pp->tm_source);
		pp->tm_source = NULL;
	}
	if (pp->sock_fd >= 0) {
		close(pp->sock_fd);
		pp->sock_fd = -1;
	}
	if (pp->is_dummy && pp->peer)
		free(pp->peer); /* private throwaway peer, never in the table */

	sd_bus_message_unref(pp->call);
	free(pp);
}

static struct peer *ping_resolve_peer(struct pending_ping *pp)
{
	if (pp->is_dummy)
		return NULL;
	return find_peer_by_addr(pp->ctx, pp->eid,
				 pp->req_addr.smctp_base.smctp_network);
}

static void pending_ping_reply_success(struct pending_ping *pp)
{
	struct peer *peer = ping_resolve_peer(pp);
	if (peer)
		peer->ping_failed_once = false;

	sd_bus_reply_method_return(pp->call, NULL);
	cleanup_pending_ping(pp);
}

static void pending_ping_reply_error(struct pending_ping *pp, int errcode)
{
	struct peer *peer = ping_resolve_peer(pp);
	if (peer)
		peer->ping_failed_once = true;

	sd_bus_error berr = SD_BUS_ERROR_NULL;
	set_berr(pp->ctx, errcode, &berr);
	sd_bus_reply_method_error(pp->call, &berr);
	sd_bus_error_free(&berr);
	cleanup_pending_ping(pp);
}

static int cb_ping_response(sd_event_source *s, int fd, uint32_t revents,
			    void *data)
{
	struct pending_ping *pp = data;

	if (revents & EPOLLERR) {
		/* Dummy peers are transient probes of unknown EIDs; don't
		 * surface their error-queue noise. */
		read_mctp_error_queue(pp->ctx, fd,
				      pp->ctx->verbose && !pp->is_dummy,
				      &pp->req_addr);
		if (!(revents & EPOLLIN)) {
			pending_ping_reply_error(pp, -EIO);
			return 0;
		}
	}

	if (revents & EPOLLIN) {
		uint8_t *buf = NULL;
		size_t buf_size = 0;
		struct sockaddr_mctp_ext resp_addr = { 0 };
		int rc;

		struct peer *peer = ping_resolve_peer(pp);
		bool suppress_log =
			pp->is_dummy || (peer && peer->ping_failed_once);
		rc = read_message(pp->ctx, fd, &buf, &buf_size, &resp_addr,
				  suppress_log);
		free(buf);

		if (rc < 0 || buf_size == 0) {
			pending_ping_reply_error(pp, rc < 0 ? rc : -EPROTO);
			return 0;
		}

		pending_ping_reply_success(pp);
	}

	return 0;
}

static int cb_ping_timeout(sd_event_source *s, uint64_t usec, void *data)
{
	struct pending_ping *pp = data;

	/* Report the timeout only on the first failure of a streak; suppress
	 * repeats until a successful ping re-arms ping_failed_once. Dummy peers
	 * don't persist across pings, so never report for them. Re-resolve the
	 * peer pointer at callback time — the raw pointer stored at ping
	 * dispatch may have been freed by remove_peer() while in flight. */
	struct peer *peer = ping_resolve_peer(pp);
	if (!pp->is_dummy && !(peer && peer->ping_failed_once))
		report_transaction_error(pp->ctx, ETIMEDOUT, MCTP_DIR_RX,
					 &pp->req_addr, NULL, 0);
	pending_ping_reply_error(pp, -ETIMEDOUT);
	return 0;
}

static int method_endpoint_ping(sd_bus_message *call, void *data,
				sd_bus_error *berr)
{
	struct net *net = data;
	struct ctx *ctx = net->ctx;
	mctp_eid_t eid;
	struct peer *peer;
	struct mctp_ctrl_cmd_get_uuid req = { 0 };
	dest_phys dest = { 0 };
	bool is_dummy = false;
	int sd = -1, val;
	ssize_t rc;
	struct pending_ping *pp = NULL;

	rc = sd_bus_message_read_basic(call, 'y', &eid);
	if (rc < 0) {
		sd_bus_error_set_errno(berr, -rc);
		return rc;
	}

	if (eid < 8 || eid == 0xff) {
		return sd_bus_error_setf(berr, SD_BUS_ERROR_INVALID_ARGS,
					 "Invalid EID %d", eid);
	}

	/* Find the peer by EID in this network */
	peer = find_peer_by_addr(ctx, eid, net->net);
	if (!peer) {
		/* create dummy peer for querying then later remove it */
		peer = calloc(1, sizeof(*peer));
		if (!peer) {
			rc = -ENOMEM;
			warnx("Failed to allocate memory for dummy peer");
			goto err;
		}
		peer->ctx = ctx;
		peer->net = net->net;
		peer->eid = eid;
		peer->state = REMOTE;
		memcpy(&peer->phys, &dest, sizeof(dest));
		is_dummy = true;
	}

	if (peer->state != REMOTE) {
		/* Non-remote peer (e.g. local), treat as not-supported
		 * and return success immediately */
		if (is_dummy)
			free(peer);
		return sd_bus_reply_method_return(call, NULL);
	}

	/* Build GetUUID request */
	mctp_ctrl_msg_hdr_init_req(&req.ctrl_hdr, mctp_next_iid(ctx),
				   MCTP_CTRL_CMD_GET_ENDPOINT_UUID);

	/* Open a non-blocking MCTP socket and send the request */
	sd = mctp_ops.mctp.socket();
	if (sd < 0) {
		rc = -errno;
		goto err_peer;
	}

	val = 1;
	rc = mctp_ops.mctp.setsockopt(sd, SOL_MCTP, MCTP_OPT_ADDR_EXT, &val,
				      sizeof(val));
	if (rc < 0) {
		rc = -errno;
		goto err_close;
	}

	val = 1;
	rc = mctp_ops.mctp.setsockopt(sd, SOL_MCTP, MCTP_OPT_ENABLE_ERRQUEUE,
				      &val, sizeof(val));

	/* Build the destination address */
	struct sockaddr_mctp_ext addr = { 0 };
	addr.smctp_base.smctp_family = AF_MCTP;
	addr.smctp_base.smctp_network = peer->net;
	addr.smctp_base.smctp_addr.s_addr = peer->eid;
	addr.smctp_base.smctp_type = MCTP_CTRL_HDR_MSG_TYPE;
	addr.smctp_base.smctp_tag = MCTP_TAG_OWNER;

	/* Keep first ping failure visible, suppress only repeated retry */
	bool suppress_for_ping = peer->ping_failed_once;

	rc = mctp_ops.mctp.sendto(sd, &req, sizeof(req), 0,
				  (struct sockaddr *)&addr,
				  sizeof(struct sockaddr_mctp));

	if (rc < 0) {
		rc = -errno;
		if (ctx->verbose && !suppress_for_ping && !is_dummy)
			warnx("EndpointPing: sendto EID %d failed: %s", eid,
			      strerror(-rc));
		if (!suppress_for_ping && !is_dummy)
			report_transaction_error(ctx, -rc, MCTP_DIR_TX, &addr,
						 &req, sizeof(req));
		/* Record the failed state so a repeated sendto failure is
		 * suppressed and a later successful ping re-arms reporting. */
		peer->ping_failed_once = true;
		goto err_close;
	}

	/* Allocate async ping state */
	pp = calloc(1, sizeof(*pp));
	if (!pp) {
		rc = -ENOMEM;
		goto err_close;
	}
	pp->call = sd_bus_message_ref(call);
	if (is_dummy)
		pp->peer = peer;
	pp->ctx = ctx;
	pp->sock_fd = sd;
	pp->is_dummy = is_dummy;
	pp->eid = eid;
	pp->req_addr = addr;

	/* Add socket to the MAIN event loop — non-blocking wait for response */
	rc = sd_event_add_io(ctx->event, &pp->io_source, sd, EPOLLIN | EPOLLERR,
			     cb_ping_response, pp);
	if (rc < 0) {
		warnx("EndpointPing: sd_event_add_io failed: %s",
		      strerror(-rc));
		goto err_pp;
	}

	/* Add timeout to the MAIN event loop */
	rc = sd_event_add_time_relative(ctx->event, &pp->tm_source,
					CLOCK_MONOTONIC, ctx->mctp_timeout, 0,
					cb_ping_timeout, pp);
	if (rc < 0) {
		warnx("EndpointPing: sd_event_add_time_relative failed: %s",
		      strerror(-rc));
		goto err_pp;
	}

	/* Tell sd-bus we will reply later (return positive value) */
	return 1;

err_pp:
	cleanup_pending_ping(pp);
	set_berr(ctx, rc, berr);
	return rc;

err_close:
	close(sd);
err_peer:
	if (is_dummy)
		free(peer); /* private throwaway peer, never in the table */
err:
	set_berr(ctx, rc, berr);
	return rc;
}

static int method_get_routing_table(sd_bus_message *call, void *data,
				    sd_bus_error *berr)
{
	dest_phys desti, *dest = &desti;
	struct link *link = data;
	struct ctx *ctx = link->ctx;
	struct peer *peer = NULL;
	int rc = 0, net = 0;
	mctp_eid_t eid = 0;

	dest->ifindex = link->ifindex;
	if (dest->ifindex <= 0)
		return sd_bus_error_setf(berr, SD_BUS_ERROR_INVALID_ARGS,
					 "Unknown MCTP interface");

	rc = sd_bus_message_read(call, "y", &eid);
	if (rc < 0)
		goto err;

	net = mctp_nl_net_byindex(ctx->nl, dest->ifindex);
	peer = find_peer_by_addr(ctx, eid, net);
	if (!peer) {
		return sd_bus_error_setf(berr, SD_BUS_ERROR_INVALID_ARGS,
					 "Unknown EID");
	} else {
		if (GET_ENDPOINT_TYPE(peer->endpoint_type) !=
		    MCTP_BUS_OWNER_BRIDGE) {
			return sd_bus_error_setf(berr,
						 SD_BUS_ERROR_INVALID_ARGS,
						 "Endpoint is not a Bridge");
		} else {
			rc = query_routing_table(peer);
			if (rc < 0)
				goto err;
		}
	}
	rc = sd_bus_reply_method_return(call, "");
err:
	set_berr(ctx, rc, berr);
	return rc;
}
static int query_get_peer_routing_data(struct peer *pool_owner_peer,
				       struct peer *peer)
{
	struct mctp_ctrl_resp_get_routing_table *resp = NULL;
	struct mctp_ctrl_cmd_get_routing_table req;
	const unsigned int max_iter = 256;
	struct sockaddr_mctp_ext addr;
	unsigned int iter = 0;
	struct ctx *ctx = NULL;
	uint8_t *buf = NULL;
	size_t buf_size;
	uint8_t iid;
	int rc;

	iid = mctp_next_iid(peer->ctx);
	req.ctrl_hdr.rq_dgram_inst = RQDI_REQ | iid;
	req.ctrl_hdr.command_code = MCTP_CTRL_CMD_GET_ROUTING_TABLE_ENTRIES;
	req.entry_handle = 0;
	ctx = peer->ctx;

	while (req.entry_handle != 0xFF) {
		if (++iter > max_iter) {
			warnx("%s pagination exceeded %u iterations; aborting",
			      __func__, max_iter);
			rc = -EPROTO;
			goto out;
		}
		rc = endpoint_query_peer(pool_owner_peer,
					 MCTP_CTRL_HDR_MSG_TYPE, &req,
					 sizeof(req), &buf, &buf_size, &addr);
		if (rc < 0)
			goto out;

		rc = mctp_ctrl_validate_get_routing_table_response(
			buf, buf_size, peer_tostr_short(pool_owner_peer), iid,
			&addr, pool_owner_peer->ping_failed_once);
		if (rc)
			goto out;

		resp = (void *)buf;
		if (!resp) {
			warnx("%s Invalid response Buffer\n", __func__);
			rc = -ENOMEM;
			goto out;
		}

		if (ctx->verbose) {
			fprintf(stderr,
				"%s: returned routing entries %x, next handle %x\n",
				__func__, resp->number_of_entries,
				resp->next_entry_handle);
		}

		if (resp->number_of_entries) {
			struct get_routing_table_entry *entry =
				(struct get_routing_table_entry *)
					resp->routing_entries;
			for (uint8_t idx = 0; idx < resp->number_of_entries;
			     idx++) {
				if (entry->starting_eid == peer->eid) {
					size_t entry_size =
						sizeof(struct get_routing_table_entry) +
						entry->phys_address_size;
					peer->routing_table_entry =
						(struct get_routing_table_entry
							 *)malloc(entry_size);
					if (!peer->routing_table_entry) {
						warnx("Failed to allocate memory for local routing");
						rc = -ENOMEM;
						goto out;
					}
					memset(peer->routing_table_entry, 0,
					       entry_size);
					memcpy(peer->routing_table_entry, entry,
					       entry_size);
					free(buf);
					return 0;
				}
				// Advance to next entry: fixed structure size + variable phys_address data
				entry = (struct get_routing_table_entry *)
					routing_table_entry_next(entry);
			}
		}
		/* If bridge returns 0 after we've already started paginating,
		 * treat as end-of-table rather than restarting from 0. */
		if ((resp->next_entry_handle == 0 && req.entry_handle != 0) ||
		    (resp->next_entry_handle == req.entry_handle)) {
			warnx("Unexpected routing table entry handle 0 after %u iterations",
			      iter);
			free(peer->routing_table_entry);
			peer->routing_table_entry = NULL;
			return -ERANGE;
		}
		req.entry_handle = resp->next_entry_handle;
		free(buf);
	}
	return 0;
out:
	free(buf);
	return rc;
}
// Query various properties of a peer.
// To be called when a new peer is discovered/assigned, once an EID is known
// and routable.
static int query_peer_properties(struct peer *peer)
{
	struct peer *pool_owner_peer = NULL;
	const unsigned int max_retries = 4;
	uint8_t uuid[16] = { 0 };
	struct net *n = NULL;
	int rc;

	for (unsigned int i = 0; i < max_retries; i++) {
		rc = query_get_peer_msgtypes(peer);

		// Success
		if (rc == 0)
			break;

		// On timeout, retry
		if (rc == -ETIMEDOUT) {
			if (i == max_retries - 1)
				goto out;

			if (peer->ctx->verbose)
				warnx("Retrying to get endpoint types for %s. Attempt %u",
				      peer_tostr(peer), i + 1);
			rc = 0;
			continue;
		}

		// On other errors, warn and ignore
		if (rc < 0) {
			if (peer->ctx->verbose)
				warnx("Error getting endpoint types for %s. Error %d %s",
				      peer_tostr(peer), -rc, strerror(-rc));
			goto out;
		}
	}

	for (unsigned int i = 0; i < max_retries; i++) {
		rc = query_get_peer_uuid(peer, uuid);

		// Success
		if (rc == 0) {
			peer_set_uuid(peer, uuid);
			break;
		}

		// On timeout, retry
		if (rc == -ETIMEDOUT) {
			if (i == max_retries - 1)
				goto out;

			if (peer->ctx->verbose)
				warnx("Retrying to get peer UUID for %s. Attempt %u",
				      peer_tostr(peer), i + 1);
			rc = 0;
			continue;
		}

		// On other errors, warn and ignore
		if (rc < 0 && rc != -ENOTSUP) {
			if (peer->ctx->verbose)
				warnx("Error getting UUID for %s. Error %d %s",
				      peer_tostr(peer), rc, strerror(-rc));
			goto out;
		} else {
			if (rc == -ENOTSUP) {
				// If UUID is not supported (ENOTSUP), we want to fake out the UUID
				// to be such that uuid[15] is the EID. This is a hack to allow
				// clients to still use the UUID property even if the device
				// doesn't support it (For ex. certain NVMe drives)
				uuid[15] = peer->eid;
				rc = 0;
			}
			peer_set_uuid(peer, uuid);
			break;
		}
	}

	mctp_eid_t eid;
	uint8_t ep_type, medium_spec;
	rc = query_get_endpoint_id(peer->ctx, &peer->phys, &eid, &ep_type,
				   &medium_spec, peer);
	if (rc < 0) {
		if (peer->ctx->verbose)
			warnx("Error getting endpoint ID for %s. Ignoring error %d %s",
			      peer_tostr(peer), rc, strerror(-rc));
		rc = 0;
	} else {
		if (peer->eid == eid) {
			peer->endpoint_type = ep_type;
			peer->medium_spec = medium_spec;
		} else {
			warnx("GET_ENDPOINT_ID: Endpoint ID mismatch for %s: %d != %d",
			      peer_tostr(peer), peer->eid, eid);
		}
	}

	n = lookup_net(peer->ctx, peer->net);
	if (!peer->routing_table_entry &&
	    is_eid_in_bridge_pool(n, peer->ctx, peer->eid, &pool_owner_peer)) {
		if (peer->pool_owner_eid != pool_owner_peer->eid) {
			peer->phys.hwaddr_len =
				pool_owner_peer->phys.hwaddr_len;
			peer->phys.ifindex = pool_owner_peer->phys.ifindex;
			peer->pool_owner_eid = pool_owner_peer->eid;
			peer->local_eid = pool_owner_peer->local_eid;
			peer->is_direct_endpoint = false;
			peer->num_ignore_message_types =
				pool_owner_peer->num_ignore_message_types;
			peer->ignore_message_types = malloc(
				pool_owner_peer->num_ignore_message_types);
			if (peer->num_ignore_message_types &&
			    !peer->ignore_message_types) {
				warnx("Failed to allocate memory for ignore message types");
				rc = -ENOMEM;
				goto out;
			}
			memset(peer->ignore_message_types, 0,
			       pool_owner_peer->num_ignore_message_types);
			memcpy(peer->phys.hwaddr, pool_owner_peer->phys.hwaddr,
			       pool_owner_peer->phys.hwaddr_len);
			memcpy(peer->ignore_message_types,
			       pool_owner_peer->ignore_message_types,
			       pool_owner_peer->num_ignore_message_types);
		}

		rc = query_get_peer_routing_data(pool_owner_peer, peer);
		if (rc < 0) {
			if (peer->ctx->verbose)
				warnx("Error getting routing data for %s. Ignoring error %d %s",
				      peer_tostr(peer), rc, strerror(-rc));
			rc = 0;
		}
		if (!peer->routing_table_entry) {
			warnx("No routing data found for %s", peer_tostr(peer));
		}
	}

out:
	// TODO: emit property changed? Though currently they are all const.
	return rc;
}

static int peer_neigh_update(struct peer *peer, uint16_t type)
{
	struct {
		struct nlmsghdr nh;
		struct ndmsg ndmsg;
		uint8_t rta_buff[RTA_SPACE(1) + RTA_SPACE(MAX_ADDR_LEN)];
	} msg = { 0 };
	size_t rta_len = sizeof(msg.rta_buff);
	struct rtattr *rta = (void *)msg.rta_buff;

	msg.nh.nlmsg_type = type;
	msg.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	msg.ndmsg.ndm_ifindex = peer->phys.ifindex;
	msg.ndmsg.ndm_family = AF_MCTP;
	msg.nh.nlmsg_len = NLMSG_LENGTH(sizeof(msg.ndmsg));
	msg.nh.nlmsg_len += mctp_put_rtnlmsg_attr(
		&rta, &rta_len, NDA_DST, &peer->eid, sizeof(peer->eid));
	msg.nh.nlmsg_len += mctp_put_rtnlmsg_attr(&rta, &rta_len, NDA_LLADDR,
						  peer->phys.hwaddr,
						  peer->phys.hwaddr_len);
	return mctp_nl_send(peer->ctx->nl, &msg.nh);
}

// type is RTM_NEWROUTE or RTM_DELROUTE
static int peer_route_update(struct peer *peer, uint16_t type)
{
	// temp : avoid abort for test in case routes were not removed
	// till kernel bug to remove gateway routes is fixed
	if (type == RTM_NEWROUTE) {
		if (!mctp_nl_if_exists(peer->ctx->nl, peer->phys.ifindex)) {
			bug_warn("%s: Unknown ifindex %d", __func__,
				 peer->phys.ifindex);
			return -ENODEV;
		}
		return mctp_nl_route_add(peer->ctx->nl, peer->eid, 0,
					 peer->phys.ifindex, NULL, peer->mtu);
	} else if (type == RTM_DELROUTE) {
		if (peer->pool_size > 0) {
			int rc = del_pool_gw_routes_ignore_aware(peer);
			if (rc < 0)
				warnx("failed to delete route for peer pool eids %d-%d %s",
				      peer->pool_start,
				      peer->pool_start + peer->pool_size - 1,
				      strerror(-rc));
		}
		if (!mctp_nl_if_exists(peer->ctx->nl, peer->phys.ifindex)) {
			return -ENODEV;
		}
		return mctp_nl_route_del(peer->ctx->nl, peer->eid, 0,
					 peer->phys.ifindex, NULL);
	}

	bug_warn("%s: bad type %d", __func__, type);
	return -EPROTO;
}

/* Called when a new peer is discovered. Queries properties and publishes */
static int setup_added_peer(struct peer *peer)
{
	struct net *n = lookup_net(peer->ctx, peer->net);
	int rc;

	if (!n) {
		bug_warn("%s Bad net %u", __func__, peer->net);
		return -EPROTO;
	}
	// Set minimum MTU by default for compatibility. Clients can increase
	// this with .SetMTU as needed
	peer->mtu = mctp_nl_min_mtu_byindex(peer->ctx->nl, peer->phys.ifindex);

	// add route before querying for non-bridged endpoints.
	// bridged endpoints will use the bridge's pool range route.
	if (!is_eid_in_bridge_pool(n, peer->ctx, peer->eid, NULL)) {
		warnx("Adding route for non-bridged endpoint %s",
		      peer_tostr(peer));
		add_peer_route(peer);
	}

	rc = query_peer_properties(peer);
	if (rc < 0)
		goto out;

	rc = publish_peer(peer, true);
out:
	if (rc < 0) {
		remove_peer(peer);
	}
	return rc;
}

static void add_peer_neigh(struct peer *peer)
{
	size_t if_hwaddr_len;
	int rc;

	rc = mctp_nl_hwaddr_len_byindex(peer->ctx->nl, peer->phys.ifindex,
					&if_hwaddr_len);
	if (rc) {
		warnx("Missing neigh ifindex %d", peer->phys.ifindex);
		return;
	}

	if (peer->phys.hwaddr_len == 0 && if_hwaddr_len == 0) {
		// Don't add neigh entries for address-less transports
		// We'll let the kernel reject mismatching entries.
		return;
	}

	if (peer->ctx->verbose) {
		fprintf(stderr, "Adding neigh to %s\n", peer_tostr(peer));
	}
	rc = peer_neigh_update(peer, RTM_NEWNEIGH);
	if (rc < 0 && rc != -EEXIST) {
		warnx("Failed adding neigh for %s: %s", peer_tostr(peer),
		      strerror(-rc));
	} else {
		peer->have_neigh = true;
	}
}

/* Adds routes/neigh. This is separate from
   publish_peer() because we want a two stage setup of querying
   properties (routed packets) then emitting dbus once finished */
static void add_peer_route(struct peer *peer)
{
	int rc;

	// We always try to add routes/neighs, ignoring if they
	// already exist.

	add_peer_neigh(peer);

	if (peer->ctx->verbose) {
		fprintf(stderr, "Adding route to %s\n", peer_tostr(peer));
	}
	rc = peer_route_update(peer, RTM_NEWROUTE);
	if (rc < 0 && rc != -EEXIST) {
		warnx("Failed adding route for %s: %s", peer_tostr(peer),
		      strerror(-rc));
	} else {
		peer->have_route = true;
	}
}

/* Sets up routes/neigh, creates dbus object and emits added signal */
static int publish_peer(struct peer *peer, bool add_route)
{
	int rc = 0;
	struct net *n = NULL;
	n = lookup_net(peer->ctx, peer->net);

	if (add_route && peer->state == REMOTE && !peer->have_route &&
	    !is_eid_in_bridge_pool(n, peer->ctx, peer->eid, NULL)) {
		warnx("Adding route for non-bridged endpoint %s",
		      peer_tostr(peer));
		add_peer_route(peer);
	}

	if (peer->published) {
		// If we are trying to publish again, this could be case of endpoint reset
		// more specifically direct endpoint reset, need to replicate what we did
		// for bridge to notify other application eg GPU fast reset
		rc = sd_bus_emit_properties_changed(peer->ctx->bus, peer->path,
						    CC_MCTP_DBUS_IFACE_ENDPOINT,
						    "Connectivity", NULL);
		if (rc < 0) {
			warnx("%s: Connectivity change emit failed: %d %s",
			      __func__, rc, strerror(-rc));
		}
		if (peer->ctx->verbose) {
			fprintf(stderr, "Refreshed eid property %d\n",
				peer->eid);
		}
		return 0;
	}

	rc = asprintf(&peer->path, "%s/networks/%d/endpoints/%d",
		      MCTP_DBUS_PATH, peer->net, peer->eid);
	if (rc < 0)
		return -ENOMEM;

	peer->published = true;

	sd_bus_add_object_vtable(peer->ctx->bus, &peer->slot_obmc_endpoint,
				 peer->path, MCTP_DBUS_IFACE_ENDPOINT,
				 bus_endpoint_obmc_vtable, peer);

	sd_bus_add_object_vtable(peer->ctx->bus, &peer->slot_cc_endpoint,
				 peer->path, CC_MCTP_DBUS_IFACE_ENDPOINT,
				 bus_endpoint_cc_vtable, peer);

	if (peer->uuid) {
		sd_bus_add_object_vtable(peer->ctx->bus, &peer->slot_uuid,
					 peer->path, OPENBMC_IFACE_COMMON_UUID,
					 bus_endpoint_uuid_vtable, peer);
	}

	sd_bus_add_object_vtable(peer->ctx->bus, &peer->slot_binding_endpoint,
				 peer->path, MCTP_DBUS_IFACE_BINDING,
				 bus_endpoint_binding_vtable, peer);

	rc = emit_endpoint_added(peer);
	if (rc > 0)
		rc = 0;

	return rc;
}

/* removes route, neigh, dbus entry for the peer */
static int unpublish_peer(struct peer *peer)
{
	int rc;
	if (peer->have_neigh) {
		if (peer->ctx->verbose) {
			fprintf(stderr, "Deleting neigh to %s\n",
				peer_tostr(peer));
		}
		rc = peer_neigh_update(peer, RTM_DELNEIGH);
		if (rc < 0) {
			warnx("Failed removing neigh for %s: %s",
			      peer_tostr(peer), strerror(-rc));
		} else {
			peer->have_neigh = false;
		}
	}

	if (peer->have_route) {
		if (peer->ctx->verbose) {
			fprintf(stderr, "Deleting route to %s\n",
				peer_tostr(peer));
		}
		rc = peer_route_update(peer, RTM_DELROUTE);
		if (rc < 0) {
			warnx("Failed removing route for %s: %s",
			      peer_tostr(peer), strerror(-rc));
		} else {
			peer->have_route = false;
		}
	}
	if (peer->published) {
		emit_endpoint_removed(peer);
		sd_bus_slot_unref(peer->slot_obmc_endpoint);
		peer->slot_obmc_endpoint = NULL;
		sd_bus_slot_unref(peer->slot_cc_endpoint);
		peer->slot_cc_endpoint = NULL;
		sd_bus_slot_unref(peer->slot_bridge);
		peer->slot_bridge = NULL;
		sd_bus_slot_unref(peer->slot_uuid);
		peer->slot_uuid = NULL;
		sd_bus_slot_unref(peer->slot_binding_endpoint);
		peer->slot_binding_endpoint = NULL;
		peer->published = false;
		free(peer->path);
	}

	return 0;
}

static int method_endpoint_remove(sd_bus_message *call, void *data,
				  sd_bus_error *berr)
{
	struct peer *peer = data;
	int rc;
	struct ctx *ctx = peer->ctx;

	if (peer->state == LOCAL)
		return sd_bus_error_setf(berr, SD_BUS_ERROR_FAILED,
					 "Cannot remove mctpd-local endpoint");
	if (!peer->published) {
		rc = -EPROTO;
		goto out;
	}

	rc = remove_peer(peer);
	if (rc < 0)
		goto out;

	rc = sd_bus_reply_method_return(call, "");
out:
	set_berr(ctx, rc, berr);
	return rc;
}

/* FIXME: I2C-specific */
/* DSP0237 v1.2.0 Table 9 */
#define MCTP_I2C_TSYM_TRECLAIM_MIN_US 5000000
#define MCTP_I2C_TSYM_MN1_MIN 2
#define MCTP_I2C_TSYM_MT1_MAX_US 100000
#define MCTP_I2C_TSYM_MT3_MAX_US 100000
#define MCTP_I2C_TSYM_MT4_MIN_US 5000000
#define MCTP_I2C_TSYM_MT2_MIN_US \
	(MCTP_I2C_TSYM_MT1_MAX_US + 2 * MCTP_I2C_TSYM_MT3_MAX_US)
#define MCTP_I2C_TSYM_MT2_MAX_MS MCTP_I2C_TSYM_MT4_MIN_US

static int peer_endpoint_recover(sd_event_source *s, uint64_t usec,
				 void *userdata)
{
	struct peer *peer = userdata;
	struct ctx *ctx = peer->ctx;
	const char *peer_path;
	int rc;

	/*
	 * Error handling policy:
	 *
	 * 1. Any resource management error prior to Treclaim is handled by
	 *    rescheduling the poll query, unless it is scheduling the poll
	 *    query itself that fails.
	 *
	 * 2. If scheduling the poll query fails then the endpoint is removed.
	 */

	peer->recovery.npolls--;

	/*
	 * Test if we still have connectivity to the endpoint. If we do, we will get a
	 * response reporting the current EID. This is the test recommended by 8.17.6
	 * of DSP0236 v1.3.1.
	 */
	if (peer->is_direct_endpoint) {
		rc = query_get_endpoint_id(ctx, &peer->phys,
					   &peer->recovery.eid,
					   &peer->recovery.endpoint_type,
					   &peer->recovery.medium_spec,
					   /*peer=*/NULL);
	} else {
		/* Assumption: for endpoints behind the bridge, it's expected that bridge is
		 * going to reassign same EID to the endpoint if not then we can never truly
		 * access that endpoint again if eid is lost*/
		rc = query_get_endpoint_id(ctx, &peer->phys,
					   &peer->recovery.eid,
					   &peer->recovery.endpoint_type,
					   &peer->recovery.medium_spec, peer);
	}

	if (rc < 0) {
		goto reschedule;
	}

	/*
	 * If we've got a response there are two scenarios:
	 *
	 * 1. The device responds with the EID that we expect it to have
	 * 2. The device responds with an unexpected EID, e.g. 0
	 *
	 * For scenario 1 we're done as the device is responsive and has the expected
	 * address. For scenario 2, we may not yet consider the EID assignment as
	 * expired, so check the UUID for a match. If the UUID matches we reassign the
	 * expected EID to the device. If the UUID does not match we allocate a new
	 * EID for the exchanged device, given it is responsive.
	 */
	if (peer->recovery.eid != peer->eid && peer->is_direct_endpoint) {
		static const uint8_t nil_uuid[16] = { 0 };
		bool uuid_matches_peer = false;
		bool uuid_matches_nil = false;
		uint8_t uuid[16] = { 0 };
		mctp_eid_t new_eid;

		rc = query_get_peer_uuid_by_phys(ctx, &peer->phys, uuid);
		if (rc == -ENOTSUP) {
			uuid[15] = peer->eid;
			rc = 0;
		}
		if (!rc && peer->uuid) {
			static_assert(sizeof(uuid) == sizeof(nil_uuid),
				      "Unsynchronized UUID sizes");
			uuid_matches_peer =
				memcmp(uuid, peer->uuid, sizeof(uuid)) == 0;
			uuid_matches_nil =
				memcmp(uuid, nil_uuid, sizeof(uuid)) == 0;
		}

		if (rc || !uuid_matches_peer ||
		    (uuid_matches_nil && !MCTPD_RECOVER_NIL_UUID)) {
			/* It's not known to be the same device, allocate a new EID */
			dest_phys phys = peer->phys;

			assert(sd_event_source_get_enabled(
				       peer->recovery.source, NULL) == 0);
			remove_peer(peer);
			/*
			 * The representation of the old peer is now gone. Set up the new peer,
			 * after which we immediately return as there's no old peer state left to
			 * maintain.
			 */
			return endpoint_assign_eid(ctx, NULL, &phys, &peer, 0,
						   NULL, 0, false);
		}

		/* Confirmation of the same device, apply its already allocated EID */
		rc = endpoint_send_set_endpoint_id(peer, &new_eid, NULL);
		if (rc < 0) {
			goto reschedule;
		}

		if (new_eid != peer->eid) {
			rc = change_peer_eid(peer, new_eid);
			if (rc < 0) {
				goto reclaim;
			}
		}
	}

	if (peer->recovery.eid == peer->eid && !peer->is_direct_endpoint) {
		/* If the EID is the same as the expected EID and the endpoint is not direct,
		 * there could be case that behind the bridge another device is plugged in
		 * and bridge assigns the reclaimed EID to that device of now a different UUID*/

		static const uint8_t nil_uuid[16] = { 0 };
		bool uuid_matches_peer = false;
		bool uuid_matches_nil = false;
		uint8_t uuid[16] = { 0 };
		struct peer *new_peer = NULL;

		/* Query UUID by EID instead of physical address to avoid bridge UUID responses */
		rc = query_get_peer_uuid(peer, uuid);
		if (rc == -ENOTSUP) {
			uuid[15] = peer->eid;
			rc = 0;
		}
		if (rc) {
			remove_peer(peer);
			return rc;
		}
		if (!rc && peer->uuid) {
			static_assert(sizeof(uuid) == sizeof(nil_uuid),
				      "Unsynchronized UUID sizes");
			uuid_matches_peer =
				memcmp(uuid, peer->uuid, sizeof(uuid)) == 0;
			uuid_matches_nil =
				memcmp(uuid, nil_uuid, sizeof(uuid)) == 0;
		}
		if (!uuid_matches_peer ||
		    (uuid_matches_nil && !MCTPD_RECOVER_NIL_UUID)) {
			assert(sd_event_source_get_enabled(
				       peer->recovery.source, NULL) == 0);
			/* update new peer to send out remove signal and add new peer */
			struct peer *new_peer = NULL;
			dest_phys phys = peer->phys;
			mctp_eid_t new_eid = peer->eid;
			uint32_t new_net = peer->net;
			remove_peer(peer);

			rc = add_peer(ctx, &phys, new_eid, new_net, &new_peer,
				      true);
			if (rc) {
				warnx("can't add peer: %s", strerror(-rc));
				return rc;
			}
			rc = setup_added_peer(new_peer);
			if (rc) {
				warnx("can't setup added peer: %s",
				      strerror(-rc));
				return rc;
			}
			return 0;
		}
	}

	peer->degraded = false;

	peer_path = path_from_peer(peer);
	if (!peer_path)
		goto reschedule;

	rc = sd_bus_emit_properties_changed(ctx->bus, peer_path,
					    CC_MCTP_DBUS_IFACE_ENDPOINT,
					    "Connectivity", NULL);
	if (rc < 0) {
		goto reschedule;
	}

	assert(sd_event_source_get_enabled(peer->recovery.source, NULL) == 0);
	sd_event_source_unref(peer->recovery.source);
	peer->recovery.delay = 0;
	peer->recovery.source = NULL;
	peer->recovery.npolls = 0;

	return rc;

reschedule:
	if (peer->recovery.npolls > 0) {
		rc = mctp_ops.sd_event.source_set_time_relative(
			peer->recovery.source, peer->recovery.delay);
		if (rc >= 0) {
			rc = sd_event_source_set_enabled(peer->recovery.source,
							 SD_EVENT_ONESHOT);
		}
	}
	if (rc < 0) {
reclaim:
		/* Recovery unsuccessful, clean up the peer */
		assert(sd_event_source_get_enabled(peer->recovery.source,
						   NULL) == 0);
		remove_peer(peer);
	}
	return rc < 0 ? rc : 0;
}

static int method_endpoint_recover(sd_bus_message *call, void *data,
				   sd_bus_error *berr)
{
	struct peer *peer;
	bool previously;
	struct ctx *ctx;
	int rc;

	peer = data;
	ctx = peer->ctx;
	previously = peer->degraded;

	if (!previously) {
		assert(!peer->recovery.delay);
		assert(!peer->recovery.source);
		assert(!peer->recovery.npolls);
		peer->recovery.npolls = MCTP_I2C_TSYM_MN1_MIN + 1;
		peer->recovery.delay =
			(MCTP_I2C_TSYM_TRECLAIM_MIN_US / 2) - ctx->mctp_timeout;
		rc = mctp_ops.sd_event.add_time_relative(
			ctx->event, &peer->recovery.source, CLOCK_MONOTONIC, 0,
			ctx->mctp_timeout, peer_endpoint_recover, peer);
		if (rc < 0) {
			goto out;
		}

		peer->degraded = true;

		rc = sd_bus_emit_properties_changed(
			sd_bus_message_get_bus(call),
			sd_bus_message_get_path(call),
			sd_bus_message_get_interface(call), "Connectivity",
			NULL);
		if (rc < 0) {
			goto out;
		}
	}

	rc = sd_bus_reply_method_return(call, NULL);

out:
	if (rc < 0 && !previously) {
		if (peer->degraded) {
			/* Cleanup the timer if it was setup successfully. */
			sd_event_source_set_enabled(peer->recovery.source,
						    SD_EVENT_OFF);
			sd_event_source_unref(peer->recovery.source);
		}
		peer->degraded = previously;
		peer->recovery.delay = 0;
		peer->recovery.source = NULL;
		peer->recovery.npolls = 0;
	}
	set_berr(ctx, rc, berr);
	return rc;
}

static int method_endpoint_set_mtu(sd_bus_message *call, void *data,
				   sd_bus_error *berr)
{
	struct peer *peer = data;
	struct ctx *ctx = peer->ctx;
	int rc;
	uint32_t mtu;

	if (peer->state == LOCAL)
		return sd_bus_error_setf(berr, SD_BUS_ERROR_FAILED,
					 "Cannot set local endpoint MTU");

	rc = sd_bus_message_read(call, "u", &mtu);
	if (rc < 0)
		goto out;

	rc = peer_set_mtu(ctx, peer, mtu);
	if (rc < 0)
		goto out;

	rc = sd_bus_reply_method_return(call, "");
out:
	set_berr(ctx, rc, berr);
	return rc;
}

static int method_net_learn_endpoint(sd_bus_message *call, void *data,
				     sd_bus_error *berr)
{
	const char *peer_path = NULL;
	struct net *net = data;
	struct ctx *ctx = net->ctx;
	dest_phys dest = { 0 };
	mctp_eid_t eid = 0;
	struct peer *peer = NULL;
	int rc;
	mctp_eid_t ret_eid;
	uint8_t ret_ep_type, ret_medium_spec;

	rc = sd_bus_message_read(call, "y", &eid);
	if (rc < 0)
		goto err;

	peer = find_peer_by_addr(ctx, eid, net->net);
	/* already known? */
	if (peer)
		return sd_bus_reply_method_return(call, "sb",
						  path_from_peer(peer), false);

	rc = add_peer(ctx, &dest, eid, net->net, &peer, true);
	if (rc) {
		warnx("can't add peer: %s", strerror(-rc));
		goto err;
	}

	rc = query_get_endpoint_id(peer->ctx, &dest, &ret_eid, &ret_ep_type,
				   &ret_medium_spec, peer);
	if (rc) {
		warnx("Error getting endpoint id for %s. error %d %s",
		      peer_tostr(peer), rc, strerror(-rc));
		goto err;
	} else if (ret_eid != eid) {
		warnx("Error getting endpoint eid %u not match expected eid %u.",
		      ret_eid, eid);
		goto err;
	}

	rc = query_peer_properties(peer);
	if (rc < 0) {
		goto err;
	}

	rc = publish_peer(peer, false);
	if (rc < 0) {
		goto err;
	}

	peer_path = path_from_peer(peer);
	if (!peer_path)
		goto err;
	return sd_bus_reply_method_return(call, "sb", peer_path, 1);
err:
	if (peer) {
		remove_peer(peer);
	}

	set_berr(ctx, rc, berr);
	return rc;
}

static int on_dbus_peer_removed(sd_bus_track *track, void *userdata)
{
	struct ctx *ctx = userdata;
	size_t i, msg_types = ctx->num_supported_msg_types;

	for (i = 0; i < msg_types; i++) {
		struct msg_type_support *msg_type =
			&ctx->supported_msg_types[i];

		if (msg_type->source_peer != track)
			continue;

		free(msg_type->versions);
		*msg_type = ctx->supported_msg_types[msg_types - 1];
		ctx->num_supported_msg_types--;
		break;
	}
	sd_bus_track_unref(track);

	return 0;
}

static int on_dbus_peer_removed_vdm_type(sd_bus_track *track, void *userdata)
{
	struct ctx *ctx = userdata;
	size_t i;

	for (i = 0; i < ctx->num_supported_vdm_types; i++) {
		struct vdm_type_support *vdm_type =
			&ctx->supported_vdm_types[i];

		if (vdm_type->source_peer != track)
			continue;
		if (ctx->verbose) {
			warnx("Removing VDM type support entry format %d cmd_set 0x%04x",
			      vdm_type->format, vdm_type->cmd_set);
		}
		if (i != ctx->num_supported_vdm_types - 1) {
			*vdm_type = ctx->supported_vdm_types
					    [ctx->num_supported_vdm_types - 1];
		}
		ctx->num_supported_vdm_types--;
		break;
	}

	sd_bus_track_unref(track);
	return 0;
}

static int method_register_type_support(sd_bus_message *call, void *data,
					sd_bus_error *berr)
{
	struct msg_type_support *msg_types, *cur_msg_type;
	const uint32_t *versions = NULL;
	size_t i, versions_len;
	struct ctx *ctx = data;
	uint8_t msg_type;
	int rc;

	rc = sd_bus_message_read(call, "y", &msg_type);
	if (rc < 0)
		goto err;
	if (msg_type == 0 || msg_type >= MCTP_TYPE_VENDOR_PCIE) {
		return sd_bus_error_setf(berr, SD_BUS_ERROR_INVALID_ARGS,
					 "Invalid message type %d", msg_type);
	}
	rc = sd_bus_message_read_array(call, 'u', (const void **)&versions,
				       &versions_len);
	if (rc < 0)
		goto err;

	if (versions_len == 0) {
		warnx("No versions provided for message type %d", msg_type);
		return sd_bus_error_setf(
			berr, SD_BUS_ERROR_INVALID_ARGS,
			"No versions provided for message type %d", msg_type);
	}

	for (i = 0; i < ctx->num_supported_msg_types; i++) {
		if (ctx->supported_msg_types[i].msg_type == msg_type) {
			warnx("Message type %d already registered", msg_type);
			return sd_bus_error_setf(
				berr, SD_BUS_ERROR_INVALID_ARGS,
				"Message type %d already registered", msg_type);
		}
	}

	msg_types = realloc(ctx->supported_msg_types,
			    (ctx->num_supported_msg_types + 1) *
				    sizeof(struct msg_type_support));
	if (!msg_types) {
		return sd_bus_error_setf(
			berr, SD_BUS_ERROR_NO_MEMORY,
			"Failed to allocate memory for message types");
	}
	ctx->supported_msg_types = msg_types;

	cur_msg_type = &ctx->supported_msg_types[ctx->num_supported_msg_types];
	cur_msg_type->source_peer = NULL;
	cur_msg_type->versions = NULL;
	rc = sd_bus_track_new(ctx->bus, &cur_msg_type->source_peer,
			      on_dbus_peer_removed, ctx);
	if (rc < 0) {
		warnx("Failed to create dbus track for message type %d: %s",
		      msg_type, strerror(-rc));
		goto track_err;
	}

	rc = sd_bus_track_add_sender(cur_msg_type->source_peer, call);
	if (rc < 0) {
		warnx("Failed to add dbus track for message type %d: %s",
		      msg_type, strerror(-rc));
		goto track_err;
	}

	cur_msg_type->msg_type = msg_type;
	cur_msg_type->num_versions = versions_len / sizeof(uint32_t);
	cur_msg_type->versions = malloc(versions_len);
	if (!cur_msg_type->versions) {
		goto track_err;
	}
	// Assume callers's responsibility to provide version in uint32 format from spec
	memcpy(cur_msg_type->versions, versions, versions_len);

	ctx->num_supported_msg_types++;

	return sd_bus_reply_method_return(call, "");

track_err:
	// Extra memory for last msg type will remain allocated but tracked
	sd_bus_track_unref(cur_msg_type->source_peer);
	set_berr(ctx, rc, berr);
	return rc;

err:
	set_berr(ctx, rc, berr);
	return rc;
}

static int method_register_vdm_type_support(sd_bus_message *call, void *data,
					    sd_bus_error *berr)
{
	struct vdm_type_support new_vdm, *cur_vdm_type, *new_vdm_types_arr;
	const char *vid_type_str;
	struct ctx *ctx = data;
	uint8_t vid_format;
	uint16_t vid_pcie;
	uint32_t vid_iana;
	int rc;

	rc = sd_bus_message_read(call, "y", &vid_format);
	if (rc < 0)
		goto err;
	new_vdm.format = vid_format;

	rc = sd_bus_message_peek_type(call, NULL, &vid_type_str);
	if (rc < 0) {
		return sd_bus_error_setf(berr, SD_BUS_ERROR_INVALID_ARGS,
					 "Failed to read variant type");
	}

	if (new_vdm.format == VID_FORMAT_PCIE) {
		if (strcmp(vid_type_str, "q") != 0) {
			return sd_bus_error_setf(
				berr, SD_BUS_ERROR_INVALID_ARGS,
				"Expected format is PCIe but variant contains '%s'",
				vid_type_str);
		}
		rc = sd_bus_message_read(call, "v", "q", &vid_pcie);
		if (rc < 0)
			goto err;
		new_vdm.vendor_id.pcie = vid_pcie;
	} else if (new_vdm.format == VID_FORMAT_IANA) {
		if (strcmp(vid_type_str, "u") != 0) {
			return sd_bus_error_setf(
				berr, SD_BUS_ERROR_INVALID_ARGS,
				"Expected format is IANA but variant contains '%s'",
				vid_type_str);
		}
		rc = sd_bus_message_read(call, "v", "u", &vid_iana);
		if (rc < 0)
			goto err;
		new_vdm.vendor_id.iana = vid_iana;
	} else {
		return sd_bus_error_setf(berr, SD_BUS_ERROR_INVALID_ARGS,
					 "Unsupported VID format: %d",
					 new_vdm.format);
	}

	rc = sd_bus_message_read(call, "q", &new_vdm.cmd_set);
	if (rc < 0)
		goto err;

	// Check for duplicates
	for (size_t i = 0; i < ctx->num_supported_vdm_types; i++) {
		if (ctx->supported_vdm_types[i].format != new_vdm.format)
			continue;

		if (ctx->supported_vdm_types[i].cmd_set != new_vdm.cmd_set)
			continue;

		bool vid_matches = false;
		if (new_vdm.format == VID_FORMAT_PCIE) {
			vid_matches =
				(ctx->supported_vdm_types[i].vendor_id.pcie ==
				 new_vdm.vendor_id.pcie);
		} else {
			vid_matches =
				(ctx->supported_vdm_types[i].vendor_id.iana ==
				 new_vdm.vendor_id.iana);
		}

		if (vid_matches) {
			return sd_bus_error_setf(berr,
						 SD_BUS_ERROR_INVALID_ARGS,
						 "VDM type already registered");
		}
	}

	new_vdm_types_arr = realloc(ctx->supported_vdm_types,
				    (ctx->num_supported_vdm_types + 1) *
					    sizeof(struct vdm_type_support));
	if (!new_vdm_types_arr)
		return sd_bus_error_setf(
			berr, SD_BUS_ERROR_NO_MEMORY,
			"Failed to allocate memory for VDM types");
	ctx->supported_vdm_types = new_vdm_types_arr;

	cur_vdm_type = &ctx->supported_vdm_types[ctx->num_supported_vdm_types];
	memcpy(cur_vdm_type, &new_vdm, sizeof(struct vdm_type_support));

	// Track peer
	rc = sd_bus_track_new(ctx->bus, &cur_vdm_type->source_peer,
			      on_dbus_peer_removed_vdm_type, ctx);
	if (rc < 0)
		goto track_err;

	rc = sd_bus_track_add_sender(cur_vdm_type->source_peer, call);
	if (rc < 0)
		goto track_err;

	ctx->num_supported_vdm_types++;
	return sd_bus_reply_method_return(call, "");

track_err:
	sd_bus_track_unref(cur_vdm_type->source_peer);
	set_berr(ctx, rc, berr);
	return rc;

err:
	set_berr(ctx, rc, berr);
	return rc;
}

/* Helper function to get binding type for a peer */
static const char *get_peer_binding_type(const struct peer *peer)
{
	const char *binding_name = "Unknown";

	/* Check interface name first */
	if (peer->state == REMOTE && peer->phys.ifindex > 0) {
		const char *ifname =
			mctp_nl_if_byindex(peer->ctx->nl, peer->phys.ifindex);
		binding_name = get_binding_from_ifname(ifname);
	} else if (peer->state == LOCAL) {
		size_t num_ifs;
		int *ifs = mctp_nl_if_list(peer->ctx->nl, &num_ifs);
		if (ifs) {
			for (size_t i = 0; i < num_ifs; i++) {
				if (local_addr(peer->ctx, ifs[i]) ==
				    peer->eid) {
					const char *ifname = mctp_nl_if_byindex(
						peer->ctx->nl, ifs[i]);
					binding_name =
						get_binding_from_ifname(ifname);
					break;
				}
			}
			free(ifs);
		}
	}

	return binding_name;
}

static int bus_endpoint_get_prop(sd_bus *bus, const char *path,
				 const char *interface, const char *property,
				 sd_bus_message *reply, void *userdata,
				 sd_bus_error *berr)
{
	struct peer *peer = userdata;
	int rc;

	if (strcmp(property, "NetworkId") == 0) {
		rc = sd_bus_message_append(reply, "u", peer->net);
	} else if (strcmp(property, "EID") == 0) {
		rc = sd_bus_message_append(reply, "y", peer->eid);
	} else if (strcmp(property, "SupportedMessageTypes") == 0) {
		rc = sd_bus_message_append_array(reply, 'y',
						 peer->message_types,
						 peer->num_message_types);
	} else if (strcmp(property, "UUID") == 0 && peer->uuid) {
		const char *s = dfree(bytes_to_uuid(peer->uuid));
		rc = sd_bus_message_append(reply, "s", s);
	} else if (strcmp(property, "Connectivity") == 0) {
		rc = sd_bus_message_append(
			reply, "s", peer->degraded ? "Degraded" : "Available");
	} else if (strcmp(property, "MediumType") == 0) {
		char medium_type_str[128];
		const char *medium_type = get_peer_binding_type(peer);
		if (peer->routing_table_entry) {
			medium_type = phy_transport_binding_to_string(
				peer->routing_table_entry
					->phys_transport_binding_id);
		}
		if (!strcmp(medium_type, "VDM")) {
			medium_type = "Unspecified";
		}
		snprintf(medium_type_str, sizeof(medium_type_str),
			 "xyz.openbmc_project.MCTP.Endpoint.MediaTypes.%s",
			 medium_type);
		rc = sd_bus_message_append(reply, "s", medium_type_str);
	} else if (strcmp(property, "BindingType") == 0) {
		char binding_type_str[128];
		const char *binding_name = get_peer_binding_type(peer);
		snprintf(binding_type_str, sizeof(binding_type_str),
			 "xyz.openbmc_project.MCTP.Binding.BindingTypes.%s",
			 binding_name);
		rc = sd_bus_message_append(reply, "s", binding_type_str);
	} else if (strcmp(property, "LocalEID") == 0) {
		rc = sd_bus_message_append(reply, "y", peer->local_eid);
	} else {
		warnx("Unknown property '%s' for %s iface %s", property, path,
		      interface);
		rc = -ENOENT;
	}

	return rc;
}

// clang-format off
static const sd_bus_vtable bus_link_owner_vtable[] = {
	SD_BUS_VTABLE_START(0),

	SD_BUS_METHOD_WITH_NAMES("SetupEndpoint",
		"ay",
		SD_BUS_PARAM(physaddr),
		"yisb",
		SD_BUS_PARAM(eid)
		SD_BUS_PARAM(net)
		SD_BUS_PARAM(path)
		SD_BUS_PARAM(new),
		method_setup_endpoint,
		0),

	SD_BUS_METHOD_WITH_NAMES("AssignEndpoint",
		"ay",
		SD_BUS_PARAM(physaddr),
		"yisb",
		SD_BUS_PARAM(eid)
		SD_BUS_PARAM(net)
		SD_BUS_PARAM(path)
		SD_BUS_PARAM(new),
		method_assign_endpoint,
		0),

	SD_BUS_METHOD_WITH_NAMES("AssignEndpointStatic",
		"ayyyayay",
		SD_BUS_PARAM(physaddr)
		SD_BUS_PARAM(eid)
		SD_BUS_PARAM(start_eid)
		SD_BUS_PARAM(ignore_eids)
		SD_BUS_PARAM(ignore_message_types),
		"yisb",
		SD_BUS_PARAM(eid)
		SD_BUS_PARAM(net)
		SD_BUS_PARAM(path)
		SD_BUS_PARAM(new),
		method_assign_endpoint_static,
		0),

	SD_BUS_METHOD_WITH_NAMES("LearnEndpoint",
		"ay",
		SD_BUS_PARAM(physaddr),
		"yisb",
		SD_BUS_PARAM(eid)
		SD_BUS_PARAM(net)
		SD_BUS_PARAM(path)
		SD_BUS_PARAM(found),
		method_learn_endpoint,
		0),

	SD_BUS_METHOD_WITH_ARGS("GetRoutingTable",
		SD_BUS_ARGS("y", eid),
		SD_BUS_NO_RESULT,
		method_get_routing_table,
		0),
	SD_BUS_VTABLE_END,
};
// clang-format on

static int bus_bridge_get_prop(sd_bus *bus, const char *path,
			       const char *interface, const char *property,
			       sd_bus_message *reply, void *userdata,
			       sd_bus_error *berr)
{
	struct peer *peer = userdata;
	int rc;

	if (strcmp(property, "PoolStart") == 0) {
		rc = sd_bus_message_append(reply, "y", peer->pool_start);
	} else if (strcmp(property, "PoolEnd") == 0) {
		uint8_t pool_end = 0;
		if (peer->pool_size != 0) {
			pool_end = peer->pool_start + peer->pool_size - 1;
		}
		rc = sd_bus_message_append(reply, "y", pool_end);
	} else {
		warnx("Unknown bridge property '%s' for %s iface %s", property,
		      path, interface);
		rc = -ENOENT;
	}

	return rc;
}

static int bus_network_get_prop(sd_bus *bus, const char *path,
				const char *interface, const char *property,
				sd_bus_message *reply, void *userdata,
				sd_bus_error *berr)
{
	struct net *net = userdata;
	int rc = -ENOENT;

	if (strcmp(property, "LocalEIDs") == 0) {
		mctp_eid_t *eids = dfree(malloc(256));
		size_t num;

		rc = find_local_eids_by_net(net, &num, eids);
		if (rc < 0)
			return -ENOENT;

		rc = sd_bus_message_append_array(reply, 'y', eids, num);
	}

	return rc;
}

static int bus_link_get_prop(sd_bus *bus, const char *path,
			     const char *interface, const char *property,
			     sd_bus_message *reply, void *userdata,
			     sd_bus_error *berr)
{
	struct link *link = userdata;
	const char *link_name = NULL, *link_altname = NULL;
	int rc = 0;

	link_name = mctp_nl_if_byindex(link->ctx->nl, link->ifindex);
	if (!link_name) {
		link_name = "";
		link_altname = "";
	} else {
		link_altname = mctp_nl_altname_byname(link->ctx->nl, link_name);
		if (!link_altname) {
			link_altname = "";
		}
	}

	if (link->published && strcmp(property, "Role") == 0) {
		rc = sd_bus_message_append(reply, "s",
					   roles[link->role].dbus_val);
	} else if (strcmp(property, "Interface") == 0) {
		rc = sd_bus_message_append(reply, "s", link_name);
	} else if (strcmp(property, "Alias") == 0) {
		rc = sd_bus_message_append(reply, "s", link_altname);
	} else if (strcmp(property, "NetworkId") == 0) {
		uint32_t net =
			mctp_nl_net_byindex(link->ctx->nl, link->ifindex);
		rc = sd_bus_message_append_basic(reply, 'u', &net);
	} else {
		sd_bus_error_setf(berr, SD_BUS_ERROR_INVALID_ARGS,
				  "Unknown property.");
		rc = -ENOENT;
	}

	set_berr(link->ctx, rc, berr);
	return rc;
}

static int bus_service_readiness_get_prop(sd_bus *bus, const char *path,
					  const char *interface,
					  const char *property,
					  sd_bus_message *reply, void *userdata,
					  sd_bus_error *berr)
{
	struct link *link = userdata;
	int rc = 0;

	if (strcmp(property, "ServiceType") == 0) {
		rc = sd_bus_message_append(reply, "s", SERVICE_TYPE_MCTP_STR);
	} else if (strcmp(property, "State") == 0) {
		const char *state_str =
			(link->service_state == SERVICE_STATE_ENABLED) ?
				SERVICE_STATE_ENABLED_STR :
				SERVICE_STATE_STARTING_STR;
		rc = sd_bus_message_append(reply, "s", state_str);
	} else {
		sd_bus_error_setf(berr, SD_BUS_ERROR_INVALID_ARGS,
				  "Unknown property.");
		rc = -ENOENT;
	}

	set_berr(link->ctx, rc, berr);
	return rc;
}

static int bus_link_set_prop(sd_bus *bus, const char *path,
			     const char *interface, const char *property,
			     sd_bus_message *value, void *userdata,
			     sd_bus_error *berr)
{
	struct link *link = userdata;
	struct ctx *ctx = link->ctx;
	const char *state;
	struct role role;
	int rc = -1;

	if (strcmp(property, "Role") != 0) {
		warnx("Unknown property '%s' for %s iface %s", property, path,
		      interface);
		rc = -ENOENT;
		goto out;
	}

	rc = sd_bus_message_read(value, "s", &state);
	if (rc < 0) {
		sd_bus_error_setf(
			berr, SD_BUS_ERROR_INVALID_ARGS,
			"Unknown Role. Only Support BusOwner/EndPoint.");
		goto out;
	}

	rc = get_role(state, &role);
	if (rc < 0) {
		warnx("Invalid property value '%s' for property '%s' from interface '%s' on object '%s'",
		      state, property, interface, path);
		rc = -EINVAL;
		goto out;
	}
	link->role = role.role;
	if (link->role == ENDPOINT_ROLE_ENDPOINT && (!ctx->bmc_bridge_eid)) {
		ctx->bmc_bridge_eid = local_addr(ctx, link->ifindex);
	}

out:
	set_berr(ctx, rc, berr);
	return rc;
}

__attribute__((unused)) static int
bus_endpoint_set_prop(sd_bus *bus, const char *path, const char *interface,
		      const char *property, sd_bus_message *value,
		      void *userdata, sd_bus_error *ret_error)
{
	struct peer *peer = userdata;
	const char *connectivity;
	struct ctx *ctx = peer->ctx;
	int rc;

	if (strcmp(property, "Connectivity") == 0) {
		bool previously = peer->degraded;
		rc = sd_bus_message_read(value, "s", &connectivity);
		if (rc < 0) {
			goto out;
		}
		if (strcmp(connectivity, "Available") == 0) {
			peer->degraded = false;
		} else if (strcmp(connectivity, "Degraded") == 0) {
			peer->degraded = true;
		} else {
			warnx("Invalid property value '%s' for property '%s' from interface '%s' on object '%s'",
			      connectivity, property, interface, path);
			rc = -EINVAL;
			goto out;
		}
		if (previously != peer->degraded) {
			rc = sd_bus_emit_properties_changed(
				bus, path, interface, "Connectivity", NULL);
		}
	} else {
		warnx("Unknown property '%s' in interface '%s' on object '%s'",
		      property, interface, path);
		rc = -ENOENT;
	}
out:
	set_berr(ctx, rc, ret_error);
	return rc;
}

// clang-format off
static const sd_bus_vtable bus_endpoint_obmc_vtable[] = {
	SD_BUS_VTABLE_START(0),
	SD_BUS_PROPERTY("NetworkId",
			"u",
			bus_endpoint_get_prop,
			0,
			SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("EID",
			"y",
			bus_endpoint_get_prop,
			0,
			SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("SupportedMessageTypes",
			"ay",
			bus_endpoint_get_prop,
			0,
			SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("MediumType",
			"s",
			bus_endpoint_get_prop,
			0,
			SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("LocalEID",
			"y",
			bus_endpoint_get_prop,
			0,
			SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_VTABLE_END
};

static const sd_bus_vtable bus_endpoint_uuid_vtable[] = {
	SD_BUS_VTABLE_START(0),
	SD_BUS_PROPERTY("UUID",
			"s",
			bus_endpoint_get_prop,
			0,
			SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_VTABLE_END
};

static const sd_bus_vtable bus_endpoint_binding_vtable[] = {
	SD_BUS_VTABLE_START(0),
	SD_BUS_PROPERTY("BindingType",
			"s",
			bus_endpoint_get_prop,
			0,
			SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_VTABLE_END
};

static const sd_bus_vtable bus_endpoint_cc_vtable[] = {
	SD_BUS_VTABLE_START(0),
	SD_BUS_METHOD_WITH_ARGS("SetMTU",
		SD_BUS_ARGS("u", mtu),
		SD_BUS_NO_RESULT,
		method_endpoint_set_mtu,
		0),
	SD_BUS_METHOD_WITH_ARGS("Remove",
		SD_BUS_NO_ARGS,
		SD_BUS_NO_RESULT,
		method_endpoint_remove,
		0),
	SD_BUS_METHOD("Recover",
		SD_BUS_NO_ARGS,
		SD_BUS_NO_RESULT,
		method_endpoint_recover,
		0),
#if MCTPD_WRITABLE_CONNECTIVITY
	SD_BUS_WRITABLE_PROPERTY("Connectivity",
		"s",
		bus_endpoint_get_prop,
		bus_endpoint_set_prop,
		0,
		SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
#else
	SD_BUS_PROPERTY("Connectivity",
		"s",
		bus_endpoint_get_prop,
		0,
		SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
#endif
	SD_BUS_VTABLE_END
};

static const sd_bus_vtable bus_service_readiness_vtable[] = {
	SD_BUS_VTABLE_START(0),
	SD_BUS_PROPERTY("ServiceType",
			"s",
			bus_service_readiness_get_prop,
			0,
			SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("State",
			"s",
			bus_service_readiness_get_prop,
			0,
			SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
	SD_BUS_VTABLE_END
};
static const sd_bus_vtable bus_endpoint_bridge[] = {
	SD_BUS_VTABLE_START(0),
	SD_BUS_PROPERTY("PoolStart",
			"y",
			bus_bridge_get_prop,
			0,
			SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("PoolEnd",
			"y",
			bus_bridge_get_prop,
			0,
			SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_VTABLE_END
};

static const sd_bus_vtable bus_link_vtable[] = {
	SD_BUS_VTABLE_START(0),
	SD_BUS_WRITABLE_PROPERTY("Role",
			"s",
			bus_link_get_prop,
			bus_link_set_prop,
			0,
			SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
	SD_BUS_PROPERTY("NetworkId",
			"u",
			bus_link_get_prop,
			0,
			SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
	SD_BUS_PROPERTY("Interface",
			"s",
			bus_link_get_prop,
			0,
			SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("Alias",
			"s",
			bus_link_get_prop,
			0,
			SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_VTABLE_END
};

static const sd_bus_vtable bus_network_vtable[] = {
	SD_BUS_VTABLE_START(0),
	SD_BUS_METHOD_WITH_NAMES("LearnEndpoint",
		"y",
		SD_BUS_PARAM(physaddr),
		"sb",
		SD_BUS_PARAM(path)
		SD_BUS_PARAM(found),
		method_net_learn_endpoint,
		0),
	SD_BUS_METHOD_WITH_NAMES("EndpointPing",
		"y",
		SD_BUS_PARAM(eid),
		"",
		,
		method_endpoint_ping,
		0),
	SD_BUS_PROPERTY("LocalEIDs",
			"ay",
			bus_network_get_prop,
			0,
			SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_VTABLE_END
};

static const sd_bus_vtable mctp_base_vtable[] = {
	SD_BUS_VTABLE_START(0),
	SD_BUS_METHOD_WITH_ARGS("RegisterTypeSupport",
	SD_BUS_ARGS("y", msg_type,
	            "au", versions),
	SD_BUS_NO_RESULT,
	method_register_type_support,
	0),
        SD_BUS_METHOD_WITH_ARGS("RegisterVDMTypeSupport",
        SD_BUS_ARGS("y", format,
                    "v", format_data,
                    "q", vendor_subtype),
        SD_BUS_NO_RESULT,
        method_register_vdm_type_support,
        0),
	SD_BUS_VTABLE_END,
};
// clang-format on

static int emit_endpoint_added(const struct peer *peer)
{
	const char *path = NULL;
	int rc;

	path = path_from_peer(peer);
	if (!path)
		return -1;

	if (peer->ctx->verbose)
		warnx("emitting endpoint add: %s", path);

	rc = sd_bus_emit_object_added(peer->ctx->bus, path);
	if (rc < 0)
		warnx("%s: error emitting, %s", __func__, strerror(-rc));
	return rc;
}

static int emit_endpoint_removed(const struct peer *peer)
{
	const char *path = NULL;
	int rc;

	path = path_from_peer(peer);
	if (!path)
		return -1;

	if (peer->ctx->verbose)
		warnx("emitting endpoint remove: %s", path);

	rc = sd_bus_emit_object_removed(peer->ctx->bus, path);
	if (rc < 0)
		warnx("%s: error emitting, %s", __func__, strerror(-rc));
	return rc;
}

static int emit_net_added(struct ctx *ctx, struct net *net)
{
	int rc;

	if (ctx->verbose)
		warnx("emitting net add: %s", net->path);

	rc = sd_bus_emit_object_added(ctx->bus, net->path);
	if (rc < 0)
		warnx("%s: error emitting, %s", __func__, strerror(-rc));
	return rc;
}

static int emit_interface_added(struct link *link)
{
	int rc;

	if (link->ctx->verbose)
		warnx("emitting interface add: %s", link->path);

	rc = sd_bus_emit_object_added(link->ctx->bus, link->path);
	if (rc < 0)
		warnx("%s: error emitting, %s", __func__, strerror(-rc));

	return rc;
}

static int emit_net_removed(struct ctx *ctx, struct net *net)
{
	int rc;

	if (ctx->verbose)
		warnx("emitting net remove: %s", net->path);

	rc = sd_bus_emit_object_removed(ctx->bus, net->path);
	if (rc < 0)
		warnx("%s: error emitting, %s", __func__, strerror(-rc));
	return rc;
}

static int emit_interface_removed(struct link *link)
{
	struct ctx *ctx = link->ctx;
	int rc;

	if (link->ctx->verbose)
		warnx("emitting interface remove: %s", link->path);

	rc = sd_bus_emit_object_removed(ctx->bus, link->path);
	if (rc < 0) {
		errno = -rc;
		warn("%s: error emitting", __func__);
	}

	return rc;
}

static int setup_bus(struct ctx *ctx)
{
	sigset_t sigset;
	int rc;

	// Must use the default loop so that dfree() can use it without context.
	rc = sd_event_default(&ctx->event);
	if (rc < 0) {
		warnx("Failed creating event loop");
		goto out;
	}

	rc = sigemptyset(&sigset);
	if (rc < 0)
		goto out;

	rc = sigaddset(&sigset, SIGTERM);
	if (rc < 0)
		goto out;

	rc = sigaddset(&sigset, SIGINT);
	if (rc < 0)
		goto out;

	rc = sigprocmask(SIG_BLOCK, &sigset, NULL);
	if (rc < 0)
		goto out;

	rc = sd_event_add_signal(ctx->event, NULL, SIGTERM, NULL, NULL);
	if (rc < 0)
		goto out;

	rc = sd_event_add_signal(ctx->event, NULL, SIGINT, NULL, NULL);
	if (rc < 0)
		goto out;

	rc = sd_bus_default(&ctx->bus);
	if (rc < 0) {
		warnx("Couldn't connect to D-Bus");
		goto out;
	}

	rc = sd_bus_attach_event(ctx->bus, ctx->event,
				 SD_EVENT_PRIORITY_NORMAL);
	if (rc < 0) {
		warnx("Failed attach to event loop");
		goto out;
	}

	rc = sd_bus_add_object_manager(ctx->bus, NULL, MCTP_DBUS_PATH);
	if (rc < 0) {
		warnx("Adding object manager failed: %s", strerror(-rc));
		goto out;
	}

	rc = sd_bus_add_object_vtable(ctx->bus, NULL, MCTP_DBUS_PATH,
				      MCTP_DBUS_NAME, mctp_base_vtable, ctx);
	if (rc < 0) {
		warnx("Adding MCTP base vtable failed: %s", strerror(-rc));
		goto out;
	}

	rc = 0;
out:
	return rc;
}

int request_dbus(struct ctx *ctx)
{
	int rc;

	rc = sd_bus_request_name(ctx->bus, MCTP_DBUS_NAME, 0);
	if (rc < 0) {
		warnx("Failed requesting dbus name %s", MCTP_DBUS_NAME);
		return rc;
	}

	return 0;
}

// Deletes one local EID.
static int del_local_eid(struct ctx *ctx, uint32_t net, int eid)
{
	struct peer *peer = NULL;
	int rc;

	peer = find_peer_by_addr(ctx, eid, net);
	if (!peer) {
		bug_warn("local eid %d net %d to delete is missing", eid, net);
		return -ENOENT;
	}

	if (peer->state != LOCAL) {
		bug_warn("local eid %d net %d to delete is incorrect", eid,
			 net);
		return -EPROTO;
	}

	peer->local_count--;
	if (peer->local_count < 0) {
		bug_warn("local eid %d net %d bad refcount %d", eid, net,
			 peer->local_count);
	}

	rc = 0;
	if (peer->local_count <= 0) {
		if (ctx->verbose) {
			fprintf(stderr, "Removing local eid %d net %d\n", eid,
				net);
		}

		rc = remove_peer(peer);
	}
	return rc;
}

// Remove nets that have no interfaces
static int prune_old_nets(struct ctx *ctx)
{
	size_t i, j, num_list;
	uint32_t *net_list;

	net_list = mctp_nl_net_list(ctx->nl, &num_list);

	// iterate and discard unused nets
	for (i = 0, j = 0; i < ctx->num_nets; i++) {
		struct net *net = ctx->nets[i];

		bool found = false;
		for (size_t n = 0; n < num_list && !found; n++)
			if (net_list[n] == net->net)
				found = true;

		if (found) {
			// isn't stale
			ctx->nets[j] = net;
			j++;
		} else {
			// stale, don't keep
			for (size_t p = 0; p < 256; p++) {
				// Sanity check that no peers are used
				if (ctx->nets[i]->peers[p]) {
					bug_warn(
						"stale entry for eid %zd in deleted net %d",
						p, net->net);
				}
			}
			emit_net_removed(ctx, net);
			del_net(net);
		}
	}
	free(net_list);
	ctx->num_nets = j;
	return 0;
}

static void free_link(struct link *link)
{
	sd_bus_slot_unref(link->slot_iface);
	sd_bus_slot_unref(link->slot_busowner);
	sd_bus_slot_unref(link->slot_service_readiness);
	free(link->path);
	free(link);
}

// Removes remote peers associated with an old interface.
// Note that this link has already been removed from ctx->nl */
static int del_interface(struct link *link)
{
	struct ctx *ctx = link->ctx;
	int ifindex = link->ifindex;

	if (ctx->verbose) {
		fprintf(stderr, "Deleting interface #%d\n", ifindex);
	}
	for (size_t i = 0; i < ctx->num_peers;) {
		struct peer *p = ctx->peers[i];

		if (p->state == REMOTE && p->phys.ifindex == ifindex) {
			int rc;

			// Linux removes routes to deleted links, so no need
			// to request removal.

			// TODO: bug: gateway routes are not deleted by kernel
			// p->have_neigh = false;
			// p->have_route = false;
			rc = remove_peer(p);
			if (rc) {
				bug_warn("Error removing peer on interface "
					 "deletion, inconsistent state");
				break;
			}
		} else {
			// Removal will shift indices down, only increment
			// while skipping.
			i++;
		}
	}

	if (emit_interface_removed(link) < 0)
		warnx("Failed to remove D-Bus interface of ifindex %d",
		      link->ifindex);
	prune_old_nets(ctx);
	free_link(link);

	return 0;
}

static int rename_interface(struct ctx *ctx, struct link *link, int ifindex)
{
	const char *ifname;
	char *path;
	int rc;

	ifname = mctp_nl_if_byindex(ctx->nl, ifindex);
	if (!ifname) {
		warnx("no name for interface %d during rename?", ifindex);
		return -ENODEV;
	}

	rc = asprintf(&path, "%s/%s", MCTP_DBUS_PATH_LINKS, ifname);
	if (rc < 0)
		return -ENOMEM;

	/* remove existing dbus object */
	emit_interface_removed(link);
	sd_bus_slot_unref(link->slot_iface);
	link->slot_iface = NULL;
	sd_bus_slot_unref(link->slot_busowner);
	link->slot_busowner = NULL;
	sd_bus_slot_unref(link->slot_service_readiness);
	link->slot_service_readiness = NULL;
	free(link->path);

	/* set new path and re-add */
	link->path = path;
	sd_bus_add_object_vtable(link->ctx->bus, &link->slot_iface, link->path,
				 CC_MCTP_DBUS_IFACE_INTERFACE, bus_link_vtable,
				 link);

	// Add the service readiness interface
	sd_bus_add_object_vtable(link->ctx->bus, &link->slot_service_readiness,
				 link->path, OPENBMC_SERVICE_READINESS_IFACE,
				 bus_service_readiness_vtable, link);

	if (link->role == ENDPOINT_ROLE_BUS_OWNER) {
		sd_bus_add_object_vtable(link->ctx->bus, &link->slot_busowner,
					 link->path,
					 CC_MCTP_DBUS_IFACE_BUSOWNER,
					 bus_link_owner_vtable, link);
	}

	emit_interface_added(link);

	return 0;
}

// For program termination cleanup
static void free_links(struct ctx *ctx)
{
	size_t num;
	int *ifs;

	ifs = mctp_nl_if_list(ctx->nl, &num);
	for (size_t i = 0; i < num; i++) {
		struct link *link = mctp_nl_get_link_userdata(ctx->nl, ifs[i]);
		mctp_nl_set_link_userdata(ctx->nl, ifs[i], NULL);
		if (link) {
			free_link(link);
		}
	}
	free(ifs);
}

// Moves remote peers from old->new net.
static int change_net_interface(struct ctx *ctx, int ifindex, uint32_t old_net)
{
	uint32_t new_net = mctp_nl_net_byindex(ctx->nl, ifindex);
	struct net *old_n, *new_n;
	struct link *link;
	int rc;

	if (ctx->verbose) {
		fprintf(stderr, "Moving interface #%d %s from net %d -> %d\n",
			ifindex, mctp_nl_if_byindex(ctx->nl, ifindex), old_net,
			new_net);
	}

	link = mctp_nl_get_link_userdata(ctx->nl, ifindex);
	if (!link) {
		warnx("No link for ifindex %d", ifindex);
		return -EPROTO;
	}

	if (new_net == 0) {
		warnx("No net for ifindex %d", ifindex);
		return -EPROTO;
	}

	if (new_net == old_net) {
		// Logic below may assume they differ
		bug_warn("%s called with new=old=%d", __func__, old_net);
		return -EPROTO;
	}

	old_n = lookup_net(ctx, old_net);
	if (!old_n) {
		bug_warn("%s: Bad old net %d", __func__, old_net);
		return -EPROTO;
	}
	new_n = lookup_net(ctx, new_net);
	if (!new_n) {
		rc = add_net(ctx, new_net);
		if (rc < 0)
			return rc;
		new_n = lookup_net(ctx, new_net);
	}

	sd_bus_emit_properties_changed(ctx->bus, link->path,
				       CC_MCTP_DBUS_IFACE_INTERFACE,
				       "NetworkId", NULL);

	for (size_t i = 0; i < ctx->num_peers; i++) {
		struct peer *peer = ctx->peers[i];
		if (!(peer->state == REMOTE && peer->phys.ifindex == ifindex)) {
			// skip peers on other interfaces
			continue;
		}

		if (peer->net != old_net) {
			bug_warn("%s: Mismatch old net %d vs %d, new net %d",
				 __func__, peer->net, old_net, new_net);
			continue;
		}
		if (check_peer_struct(peer, old_n) != 0) {
			bug_warn("%s: Inconsistent state", __func__);
			return -EPROTO;
		}

		if (new_n->peers[peer->eid]) {
			// Conflict, drop it
			warnx("EID %d already exists moving net %d->%d, dropping it",
			      peer->eid, old_net, new_net);
			remove_peer(peer);
			continue;
		}

		// Move networks, change route/neigh entries, emit new dbus signals
		unpublish_peer(peer);
		new_n->peers[peer->eid] = old_n->peers[peer->eid];
		old_n->peers[peer->eid] = NULL;
		peer->net = new_net;
		rc = publish_peer(peer, true);
		if (rc) {
			warnx("Error publishing new peer eid %d, net %d after change: %s",
			      peer->eid, peer->net, strerror(-rc));
		}
	}

	prune_old_nets(ctx);
	return 0;
}

// Adds one local EID
static int add_local_eid(struct ctx *ctx, uint32_t net, int eid)
{
	struct peer *peer;
	int rc;

	if (ctx->verbose) {
		fprintf(stderr, "Adding local eid %d net %d\n", eid, net);
	}

	peer = find_peer_by_addr(ctx, eid, net);
	if (peer) {
		if (peer->state == LOCAL) {
			// Already exists, increment refcount
			peer->local_count++;
			return 0;
		} else {
			// TODO: remove the peer and add a new local one.
			warnx("Local eid %d net %d already exists?", eid, net);
			return -EPROTO;
		}
	}

	rc = add_peer(ctx, &local_phys, eid, net, &peer, false);
	if (rc < 0) {
		bug_warn("Error adding local eid %d net %d", eid, net);
		return rc;
	}
	peer->state = LOCAL;
	peer->local_count = 1;
	rc = peer_set_uuid(peer, ctx->uuid);
	if (rc < 0) {
		warnx("Failed setting local UUID: %s", strerror(-rc));
	}

	// Only advertise supporting control messages
	peer->message_types = malloc(1);
	if (peer->message_types) {
		peer->num_message_types = 1;
		peer->message_types[0] = MCTP_CTRL_HDR_MSG_TYPE;
	} else {
		warnx("Out of memory");
	}

	rc = publish_peer(peer, true);
	if (rc) {
		warnx("Error publishing local eid %d net %d", eid, net);
	}
	return 0;
}

// Adds peers for local EIDs on an interface
static int add_interface_local(struct ctx *ctx, int ifindex)
{
	mctp_eid_t *eids = NULL;
	struct link *link = NULL;
	uint32_t net;
	size_t num;
	int rc;

	if (ctx->verbose) {
		fprintf(stderr, "Adding interface #%d %s\n", ifindex,
			mctp_nl_if_byindex(ctx->nl, ifindex));
	}

	if (!mctp_nl_up_byindex(ctx->nl, ifindex))
		warnx("Warning, interface %s is down",
		      mctp_nl_if_byindex(ctx->nl, ifindex));

	net = mctp_nl_net_byindex(ctx->nl, ifindex);
	if (net == 0) {
		warnx("No net for ifindex %d", ifindex);
		return -EINVAL;
	}

	// Add new net if required
	if (!lookup_net(ctx, net)) {
		rc = add_net(ctx, net);
		if (rc < 0)
			return rc;
	}
	eids = mctp_nl_addrs_byindex(ctx->nl, ifindex, &num);
	for (size_t j = 0; j < num; j++) {
		add_local_eid(ctx, net, eids[j]);
	}

	// Add new link if required
	link = mctp_nl_get_link_userdata(ctx->nl, ifindex);
	if (!link || !link->published) {
		rc = add_interface(ctx, ifindex);
		if (rc < 0)
			return rc;
	}

	free(eids);
	return 0;
}

static int add_net(struct ctx *ctx, uint32_t net_id)
{
	struct net *net, **tmp;
	int rc;

	if (lookup_net(ctx, net_id) != NULL) {
		bug_warn("add_net for existing net %d", net_id);
		return -EEXIST;
	}

	net = calloc(1, sizeof(*net));
	if (!net) {
		warn("failed to allocate net");
		return -ENOMEM;
	}

	// Initialise the new entry
	net->net = net_id;
	net->ctx = ctx;
	rc = asprintf(&net->path, "%s/%d", MCTP_DBUS_PATH_NETWORKS, net->net);
	if (rc < 0) {
		warn("%s: failed to allocate net path", __func__);
		free(net);
		return -ENOMEM;
	}

	tmp = realloc(ctx->nets, sizeof(struct net *) * (ctx->num_nets + 1));
	if (!tmp) {
		warnx("Out of memory");
		return -ENOMEM;
	}
	ctx->nets = tmp;
	ctx->nets[ctx->num_nets] = net;
	ctx->num_nets++;

	if (ctx->verbose) {
		fprintf(stderr, "net %d added, path %s\n", net->net, net->path);
	}

	sd_bus_add_object_vtable(ctx->bus, &net->slot, net->path,
				 CC_MCTP_DBUS_NETWORK_INTERFACE,
				 bus_network_vtable, net);

	emit_net_added(ctx, net);
	return 0;
}

static void del_net(struct net *net)
{
	sd_bus_slot_unref(net->slot);
	net->slot = NULL;
	net->net = 0;
	free(net->path);
	free(net);
}

static int add_interface(struct ctx *ctx, int ifindex)
{
	int rc;

	uint32_t net = mctp_nl_net_byindex(ctx->nl, ifindex);
	if (!net) {
		warnx("Can't find link index %d", ifindex);
		return -ENOENT;
	}

	const char *ifname = mctp_nl_if_byindex(ctx->nl, ifindex);
	if (!ifname) {
		warnx("Can't find link name for index %d", ifindex);
		return -ENOENT;
	}

	uint8_t phys_binding = mctp_nl_phys_binding_byindex(ctx->nl, ifindex);

	struct link *link = calloc(1, sizeof(*link));
	if (!link)
		return -ENOMEM;

	// Initialize slots to NULL
	link->slot_iface = NULL;
	link->slot_busowner = NULL;
	link->slot_service_readiness = NULL;

	link->discovered = DISCOVERY_UNSUPPORTED;
	link->published = false;
	link->ifindex = ifindex;
	link->ctx = ctx;
	/* Use the `mode` setting in conf/mctp.conf */
	link->role = ctx->default_role;
	/* Initialize service state to Starting */
	link->service_state = SERVICE_STATE_STARTING;
	rc = asprintf(&link->path, "%s/%s", MCTP_DBUS_PATH_LINKS, ifname);
	if (rc < 0) {
		rc = -ENOMEM;
		goto err_free;
	}

	rc = mctp_nl_set_link_userdata(ctx->nl, ifindex, link);
	if (rc < 0) {
		warnx("Failed to set UserData for link index %d", ifindex);
		goto err_free;
	}

	sd_bus_add_object_vtable(link->ctx->bus, &link->slot_iface, link->path,
				 CC_MCTP_DBUS_IFACE_INTERFACE, bus_link_vtable,
				 link);

	// Add the service readiness interface
	sd_bus_add_object_vtable(link->ctx->bus, &link->slot_service_readiness,
				 link->path, OPENBMC_SERVICE_READINESS_IFACE,
				 bus_service_readiness_vtable, link);

	if (link->role == ENDPOINT_ROLE_BUS_OWNER) {
		sd_bus_add_object_vtable(link->ctx->bus, &link->slot_busowner,
					 link->path,
					 CC_MCTP_DBUS_IFACE_BUSOWNER,
					 bus_link_owner_vtable, link);
	}

	if (phys_binding == MCTP_PHYS_BINDING_PCIE_VDM) {
		link->discovered = DISCOVERY_UNDISCOVERED;
	}

	link->published = true;
	rc = emit_interface_added(link);
	if (rc < 0) {
		link->published = false;
	}

	return rc;

err_free:
	free(link);
	return rc;
}

static int setup_nets(struct ctx *ctx)
{
	size_t num_ifs;
	int *ifs;
	int rc;

	/* Set up local addresses */
	ifs = mctp_nl_if_list(ctx->nl, &num_ifs);
	rc = 0;
	for (size_t i = 0; i < num_ifs && rc == 0; i++) {
		rc = add_interface_local(ctx, ifs[i]);
	}
	free(ifs);
	if (rc < 0)
		return rc;

	if (num_ifs == 0) {
		warnx("No MCTP interfaces");
		return -ENOENT;
	}

	if (ctx->verbose) {
		mctp_nl_linkmap_dump(ctx->nl);
	}

	return 0;
}

static void free_nets(struct ctx *ctx)
{
	for (size_t i = 0; i < ctx->num_nets; i++) {
		del_net(ctx->nets[i]);
	}

	free(ctx->nets);
}

static void print_usage(struct ctx *ctx)
{
	fprintf(stderr, "mctpd [-v] [-c FILE]\n");
	fprintf(stderr, "      -v verbose\n");
	fprintf(stderr, "      -c FILE read config from FILE\n");
}

static int parse_args(struct ctx *ctx, int argc, char **argv)
{
	struct option options[] = {
		{ .name = "help", .has_arg = no_argument, .val = 'h' },
		{ .name = "verbose", .has_arg = no_argument, .val = 'v' },
		{ .name = "config", .has_arg = required_argument, .val = 'c' },
		{ 0 },
	};
	int c;

	for (;;) {
		c = getopt_long(argc, argv, "+hvNc:", options, NULL);
		if (c == -1)
			break;

		switch (c) {
		case 'v':
			ctx->verbose = true;
			break;
		case 'c':
			ctx->config_filename = strdup(optarg);
			break;
		case 'h':
		default:
			print_usage(ctx);
			return 255;
		}
	}
	return 0;
}

static int parse_config_mode(struct ctx *ctx, const char *mode)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(roles); i++) {
		const struct role *role = &roles[i];

		if (!role->conf_val || strcmp(role->conf_val, mode))
			continue;

		ctx->default_role = role->role;
		return 0;
	}

	warnx("invalid value '%s' for mode configuration", mode);
	return -1;
}

static int fill_uuid(struct ctx *ctx)
{
	int rc;
	sd_id128_t appid;
	sd_id128_t *u = (void *)ctx->uuid;

	rc = sd_id128_from_string(mctpd_appid, &appid);
	if (rc < 0) {
		warnx("Failed to get appid");
		return rc;
	}

	rc = sd_id128_get_machine_app_specific(appid, u);
	if (rc >= 0)
		return 0;

	warnx("No machine-id, fallback to boot ID");
	rc = sd_id128_get_boot_app_specific(appid, u);
	if (rc < 0)
		warnx("Failed to get boot ID");

	return rc;
}

static int parse_config_mctp(struct ctx *ctx, toml_table_t *mctp_tab)
{
	toml_datum_t val;
	int rc;

	val = toml_int_in(mctp_tab, "message_timeout_ms");
	if (val.ok) {
		int64_t i = val.u.i;
		if (i <= 0 || i > 100 * 1000) {
			warnx("invalid message_timeout_ms value");
			return -1;
		}
		ctx->mctp_timeout = i * 1000;
	}

	val = toml_string_in(mctp_tab, "uuid");
	if (val.ok) {
		rc = sd_id128_from_string(val.u.s, (void *)&ctx->uuid);
		free(val.u.s);
		if (rc) {
			warnx("invalid UUID value");
			return rc;
		}
	} else {
		rc = fill_uuid(ctx);
		if (rc)
			return rc;
	}

	return 0;
}

static int parse_config_dyn_eid_range(struct ctx *ctx, toml_array_t *arr)
{
	int sz = toml_array_nelem(arr);
	toml_datum_t min_val, max_val;

	if (sz < 2) {
		warnx("dynamic_eid_range has invalid format - needs two elements");
		return -1;
	}
	if (sz > 2) {
		warnx("dynamic_eid_range: ignoring extra (> 2) elements");
	}

	min_val = toml_int_at(arr, 0);
	max_val = toml_int_at(arr, 1);

	if (!min_val.ok || !max_val.ok) {
		warnx("dynamic_eid_range: invalid range data");
		return -1;
	}

	if (min_val.u.i < eid_alloc_min || min_val.u.i > eid_alloc_max) {
		warnx("dynamic_eid_range: start address is invalid");
		return -1;
	}

	if (max_val.u.i < eid_alloc_min || max_val.u.i > eid_alloc_max ||
	    max_val.u.i < min_val.u.i) {
		warnx("dynamic_eid_range: end address is invalid");
		return -1;
	}

	ctx->dyn_eid_max = max_val.u.i;
	ctx->dyn_eid_min = min_val.u.i;
	return 0;
}

static int parse_config_bus_owner(struct ctx *ctx, toml_table_t *bus_owner)
{
	toml_array_t *array;
	toml_datum_t val;
	int rc;

	val = toml_int_in(bus_owner, "max_pool_size");
	if (val.ok) {
		int64_t i = val.u.i;
		if (i <= 0 || i > (ctx->dyn_eid_max - ctx->dyn_eid_min)) {
			warnx("invalid max_pool_size value (must be 1-%d)",
			      ctx->dyn_eid_max - ctx->dyn_eid_min);
			return -1;
		}
		ctx->max_pool_size = i;
	}

	array = toml_array_in(bus_owner, "dynamic_eid_range");
	if (array) {
		rc = parse_config_dyn_eid_range(ctx, array);
		if (rc)
			return rc;
	}

	val = toml_int_in(bus_owner, "endpoint_poll_ms");
	if (val.ok && val.u.i) {
		uint64_t i = val.u.i;
		if ((i > max_poll_interval_ms) || (i < min_poll_interval_ms)) {
			warnx("endpoint polling interval invalid (%lu - %lu ms)",
			      min_poll_interval_ms, max_poll_interval_ms);
			return -1;
		}

		ctx->endpoint_poll = i * 1000;
	}

	return 0;
}

static int parse_config(struct ctx *ctx)
{
	toml_table_t *conf_root, *mctp_tab, *bus_owner;
	bool conf_file_specified;
	char errbuf[256] = { 0 };
	const char *filename;
	toml_datum_t val;
	FILE *fp;
	int rc;

	conf_file_specified = !!ctx->config_filename;
	filename = ctx->config_filename ?: conf_file_default;

	rc = -1;
	fp = fopen(filename, "r");
	if (!fp) {
		/* only fatal if a configuration file was specifed by args */
		rc = 0;
		if (conf_file_specified) {
			warn("can't open configuration file %s", filename);
			rc = -1;
		}
		return rc;
	}

	conf_root = toml_parse_file(fp, errbuf, sizeof(errbuf));
	if (!conf_root) {
		warnx("can't parse configuration file %s: %s", filename,
		      errbuf);
		goto out_close;
	}

	val = toml_string_in(conf_root, "mode");
	if (val.ok) {
		rc = parse_config_mode(ctx, val.u.s);
		free(val.u.s);
		if (rc)
			goto out_free;
	}

	mctp_tab = toml_table_in(conf_root, "mctp");
	if (mctp_tab) {
		rc = parse_config_mctp(ctx, mctp_tab);
		if (rc)
			goto out_free;
	}

	bus_owner = toml_table_in(conf_root, "bus-owner");
	if (bus_owner) {
		rc = parse_config_bus_owner(ctx, bus_owner);
		if (rc)
			goto out_free;
	}

	rc = 0;

out_free:
	toml_free(conf_root);
out_close:
	fclose(fp);
	return rc;
}

static void setup_ctrl_cmd_defaults(struct ctx *ctx)
{
	ctx->supported_msg_types = NULL;
	ctx->num_supported_msg_types = 0;

	ctx->supported_vdm_types = NULL;
	ctx->num_supported_vdm_types = 0;

	// Default to supporting only control messages
	ctx->supported_msg_types = malloc(sizeof(struct msg_type_support));
	if (!ctx->supported_msg_types) {
		warnx("Out of memory for supported message types");
		return;
	}
	ctx->num_supported_msg_types = 1;
	ctx->supported_msg_types[0].msg_type = MCTP_CTRL_HDR_MSG_TYPE;

	ctx->supported_msg_types[0].versions = malloc(sizeof(uint32_t) * 4);
	if (!ctx->supported_msg_types[0].versions) {
		warnx("Out of memory for versions");
		free(ctx->supported_msg_types);
		ctx->num_supported_msg_types = 0;
		return;
	}
	ctx->supported_msg_types[0].num_versions = 4;
	ctx->supported_msg_types[0].versions[0] = htonl(0xF1F0FF00);
	ctx->supported_msg_types[0].versions[1] = htonl(0xF1F1FF00);
	ctx->supported_msg_types[0].versions[2] = htonl(0xF1F2FF00);
	ctx->supported_msg_types[0].versions[3] = htonl(0xF1F3F100);
}

static void setup_config_defaults(struct ctx *ctx)
{
	ctx->mctp_timeout = 250000; // 250ms
	ctx->default_role = ENDPOINT_ROLE_BUS_OWNER;
	ctx->max_pool_size = 15;
	ctx->dyn_eid_min = eid_alloc_min;
	ctx->dyn_eid_max = eid_alloc_max;
	ctx->bmc_ignore_eids = NULL;
	ctx->bmc_ignore_eids_count = 0;
	ctx->endpoint_poll = 0;
}

static void free_config(struct ctx *ctx)
{
	free(ctx->config_filename);
}

static void free_ctrl_cmd_defaults(struct ctx *ctx)
{
	size_t i;

	for (i = 0; i < ctx->num_supported_msg_types; i++) {
		free(ctx->supported_msg_types[i].versions);
	}
	free(ctx->supported_msg_types);
	free(ctx->supported_vdm_types);
	ctx->supported_vdm_types = NULL;
	ctx->num_supported_vdm_types = 0;
}

static int endpoint_send_allocate_endpoint_ids(
	struct peer *peer, mctp_eid_t eid_start, uint8_t eid_pool_size,
	mctp_ctrl_cmd_allocate_eids_op op, uint8_t *allocated_pool_size,
	mctp_eid_t *allocated_pool_start)
{
	struct sockaddr_mctp_ext addr;
	struct mctp_ctrl_cmd_allocate_eids req = { 0 };
	struct mctp_ctrl_resp_allocate_eids *resp = NULL;
	uint8_t *buf = NULL;
	size_t buf_size;
	uint8_t iid, stat;
	int rc;

	iid = mctp_next_iid(peer->ctx);
	mctp_ctrl_msg_hdr_init_req(&req.ctrl_hdr, iid,
				   MCTP_CTRL_CMD_ALLOCATE_ENDPOINT_IDS);
	req.alloc_eid_op = (uint8_t)(op & 0x03);
	req.pool_size = eid_pool_size;
	req.start_eid = eid_start;
	rc = endpoint_query_peer(peer, MCTP_CTRL_HDR_MSG_TYPE, &req,
				 sizeof(req), &buf, &buf_size, &addr);
	if (rc < 0)
		goto out;

	rc = mctp_ctrl_validate_response(buf, buf_size, sizeof(*resp),
					 peer_tostr_short(peer), iid,
					 MCTP_CTRL_CMD_ALLOCATE_ENDPOINT_IDS,
					 &addr, peer->ping_failed_once);

	if (rc)
		goto out;

	resp = (void *)buf;
	if (!resp) {
		warnx("%s Invalid response Buffer\n", __func__);
		return -ENOMEM;
	}

	stat = resp->status & 0x03;
	if (stat == 0x00) {
		if (peer->ctx->verbose) {
			fprintf(stderr, "Allocation accepted\n");
		}
		if (resp->eid_pool_size != eid_pool_size ||
		    resp->eid_set != eid_start) {
			warnx("Unexpected pool start %d pool size %d",
			      resp->eid_set, resp->eid_pool_size);
			rc = -1;
			goto out;
		}
	} else {
		if (stat == 0x1)
			warnx("Allocation was rejected: already allocated by other bus"
			      " pool size %d, pool start %d",
			      resp->eid_pool_size, resp->eid_set);
	}

	if (peer->ctx->verbose) {
		fprintf(stderr, "Allocated size of %d, starting from EID %d\n",
			resp->eid_pool_size, resp->eid_set);
	}

	*allocated_pool_size = resp->eid_pool_size;
	*allocated_pool_start = resp->eid_set;

out:
	free(buf);
	return rc;
}

static int mctp_ctrl_validate_completion_response(
	uint8_t *buf, size_t rsp_size, const char *peer, uint8_t iid,
	uint8_t cmd, struct sockaddr_mctp_ext *resp_addr, bool suppress_logs)
{
	struct mctp_ctrl_resp *rsp;

	if (rsp_size < sizeof(*rsp)) {
		if (!suppress_logs) {
			warnx("%s: Wrong reply length (%zu bytes)",
			      peer_cmd_prefix(peer, cmd), rsp_size);
		}
		return -ENOMSG;
	}

	rsp = (void *)buf;

	if ((rsp->ctrl_hdr.rq_dgram_inst & RQDI_IID_MASK) != iid) {
		if (!suppress_logs) {
			warnx("%s: Wrong IID (0x%02x, expected 0x%02x)",
			      peer_cmd_prefix(peer, cmd),
			      rsp->ctrl_hdr.rq_dgram_inst & RQDI_IID_MASK, iid);
			mctp_ctrl_print_response(buf, rsp_size, resp_addr,
						 suppress_logs);
		}
		return -ENOMSG;
	}

	if (rsp->ctrl_hdr.command_code != cmd) {
		if (!suppress_logs) {
			warnx("%s: Wrong opcode (0x%02x) in response",
			      peer_cmd_prefix(peer, cmd), rsp->ctrl_hdr.command_code);
			mctp_ctrl_print_response(buf, rsp_size, resp_addr,
						 suppress_logs);
		}
		return -ENOMSG;
	}

	if (rsp->completion_code) {
		if (!suppress_logs) {
			warnx("%s: Command failed, completion code 0x%02x",
			      peer_cmd_prefix(peer, cmd), rsp->completion_code);
			mctp_ctrl_print_response(buf, rsp_size, resp_addr,
						 suppress_logs);
		}
		if (rsp->completion_code == MCTP_CTRL_CC_ERROR_UNSUPPORTED_CMD)
			return -ENOTSUP;
		return -ECONNREFUSED;
	}

	return 0;
}

static int cb_populate_pool_eids(sd_event_source *s, uint64_t t, void *data)
{
	struct peer *peer = data;
	int rc;

	fprintf(stderr, "Bridge Time expired\n");
	/* call to populate RoutingTable information*/
	if (!peer) {
		bug_warn("Invalid timer expiry");
		return 0;
	}

	fprintf(stderr, "Call into GetRouting Table for EID %d\n", peer->eid);
	rc = query_routing_table(peer);
	if (rc < 0) {
		warnx("Failed to get Routing Table information\n");
	}

	// Clean up the timer reference
	sd_event_source_unref(peer->bridge_settle_timer);
	peer->bridge_settle_timer = NULL;
	// BMC as bridge :Check existing any eid cached routing data send it as Routing Info Update
	uint8_t bridge_bmc_eid = peer->ctx->bmc_bridge_eid;
	// BMC as bridge not enabled.
	if (!bridge_bmc_eid)
		return 0;

	for (uint8_t i = 0; i < peer->ctx->cache_entries.count; i++) {
		struct routing_info_entry *entry =
			(struct routing_info_entry *)peer->ctx->cache_entries
				.routing_info_entries[i];
		size_t entry_size = peer->ctx->cache_entries.entry_sizes[i];
		uint8_t entry_type = entry->entry_type & 0x0F;
		uint8_t eid_range = entry->eid_range;
		mctp_eid_t first_eid = entry->first_eid;
		uint8_t *phy_addr = entry->phys_address;
		size_t min_entry_size = routing_info_entry_size_from_phys(0);
		size_t phyaddr_size;

		if (entry_size < min_entry_size ||
		    entry_size - min_entry_size > UINT8_MAX) {
			warnx("Skipping invalid cached routing info entry size %zu",
			      entry_size);
			continue;
		}
		phyaddr_size = entry_size - min_entry_size;

		rc = endpoint_send_routing_info_update(
			peer, first_eid, eid_range, entry_type,
			(uint8_t)phyaddr_size, (!phyaddr_size) ? NULL : phy_addr);
		if (rc < 0) {
			warnx("Routing Info update [%i] failed to bridge eid %d: entry [EID %d]: [rc %s]",
			      i, peer->eid, first_eid, strerror(-rc));
		}
	}

	return 0;
}

/* DSP0236 section 8.17.6 Reclaiming EIDs from hot-plug devices
 *
 * The bus owner/bridge can detect a removed device or devices by
 * validating the EIDs that are presently allocated to endpoints that
 * are directly on the bus and identifying which EIDs are missing.
 * It can do this by attempting to access each endpoint that the bridge
 * has listed in its routing table as being a device that is directly on
 * the particular bus. Attempting to access each endpoint can be accomplished
 * by issuing the Get Endpoint ID command...


 * since bridged endpoints are routed from bridge, direct query
 * to eid should work if gateway routes are in place.
 */

static int peer_reschedule_poll(sd_event_source *source, uint64_t usec)
{
	int rc = 0;
	rc = mctp_ops.sd_event.source_set_time_relative(source, usec);
	if (rc >= 0) {
		rc = sd_event_source_set_enabled(source, SD_EVENT_ONESHOT);
	}

	return 0;
}

static int peer_endpoint_poll(sd_event_source *s, uint64_t usec, void *userdata)
{
	struct sockaddr_mctp_ext resp_addr = { 0 };
	struct mctp_ctrl_resp_get_eid *resp = NULL;
	struct sockaddr_mctp_ext req_addr = { 0 };
	struct mctp_ctrl_cmd_get_eid req = { 0 };
	mctp_eid_t pool_start, idx, ret_eid = 0;
	struct ep_poll_ctx *pctx = userdata;
	struct peer *bridge = pctx->bridge;
	sd_event_source *source = NULL;
	struct peer *peer = NULL;
	uint8_t *buf = NULL;
	size_t buf_size;
	struct net *n;
	uint8_t iid;
	int rc = 0;

	if (!bridge) {
		free(pctx);
		return 0;
	}

	pool_start = bridge->pool_start;
	mctp_eid_t ep = pctx->poll_eid;
	idx = ep - pool_start;
	source = bridge->bridge_ep_poll.sources[idx];

	/* Polling policy :
	  *
	  * Once bridge eid pool space is allocated and gateway
	  * routes for downstream endpoints are in place, busowner
	  * would initiate periodic GET_ENDPOINT_ID command at an
	  * interval of atleast 1/2 * TRECLAIM.
 
	  1. The downstream endpoint if present behind the bridge,
		 responds to send poll command, that endpoint path is
		 considered accessible.
		 The endpoint path would be published as reachable to d-bus and
		 polling will no longer continue.
 
	  2. If endpoint is not present or doesn't responds to send poll
		 commmand, then it has not been establed yet that endpoint
		 path from the bridge is accessible or not, thus continue
		 to poll.
	  */

	req_addr.smctp_base.smctp_type = MCTP_CTRL_HDR_MSG_TYPE;
	req_addr.smctp_base.smctp_network = bridge->net;
	req_addr.smctp_base.smctp_tag = MCTP_TAG_OWNER;
	req_addr.smctp_base.smctp_family = AF_MCTP;
	req_addr.smctp_base.smctp_addr.s_addr = ep;
	iid = mctp_next_iid(bridge->ctx);

	mctp_ctrl_msg_hdr_init_req(&req.ctrl_hdr, iid,
				   MCTP_CTRL_CMD_GET_ENDPOINT_ID);

	rc = endpoint_query_addr(bridge->ctx, &req_addr, false, &req,
				 sizeof(req), &buf, &buf_size, &resp_addr,
				 bridge->ping_failed_once);
	if (rc < 0) {
		free(buf);
		peer_reschedule_poll(source, bridge->ctx->endpoint_poll);
		return 0;
	}

	resp = (void *)buf;
	if (!resp) {
		warnx("Invalid response buffer");
		return -ENOMEM;
	}

	ret_eid = resp->eid;
	if (ret_eid != ep) {
		warnx("Unexpected eid %d abort polling for eid %d", ret_eid,
		      ep);
		goto exit;
	}

	if (bridge->ctx->verbose) {
		fprintf(stderr, "Endpoint %d is accessible\n", ep);
	}

	n = lookup_net(bridge->ctx, bridge->net);
	peer = n->peers[ep];
	if (!peer) {
		rc = add_peer(bridge->ctx, &(bridge->phys), ep, bridge->net,
			      &peer, true);
		if (rc < 0)
			goto exit;
	}

	rc = setup_added_peer(peer);
	if (rc < 0) {
		free(buf);
		peer_reschedule_poll(source, bridge->ctx->endpoint_poll);
		return 0;
	}

exit:
	assert(sd_event_source_get_enabled(source, NULL) == 0);
	sd_event_source_unref(source);
	bridge->bridge_ep_poll.sources[idx] = NULL;
	free(pctx);
	free(buf);
	return rc;
}

static int bridge_poll_start(struct peer *bridge)
{
	mctp_eid_t pool_start = bridge->pool_start;
	mctp_eid_t pool_size = bridge->pool_size;
	sd_event_source **sources = NULL;
	struct ctx *ctx;
	int rc;
	int i;

	sources = calloc(pool_size, sizeof(*sources));
	bridge->bridge_ep_poll.sources = sources;
	ctx = bridge->ctx;

	if (!sources) {
		rc = -ENOMEM;
		warn("Failed to setup periodic polling for bridge (eid %d)",
		     bridge->eid);
		return rc;
	}

	for (i = 0; i < pool_size; i++) {
		struct ep_poll_ctx *pctx = calloc(1, sizeof(*pctx));
		if (!pctx) {
			warnx("Failed to allocate memory, skip polling for eid %d",
			      pool_start + i);
			continue;
		}

		pctx->bridge = bridge;
		pctx->poll_eid = pool_start + i;
		rc = mctp_ops.sd_event.add_time_relative(
			ctx->event, &bridge->bridge_ep_poll.sources[i],
			CLOCK_MONOTONIC, ctx->endpoint_poll, 0,
			peer_endpoint_poll, pctx);
		if (rc < 0) {
			warnx("Failed to setup poll event source for eid %d",
			      (pool_start + i));
			free(pctx);
			continue;
		}
	}

	return 0;
}

static mctp_eid_t get_pool_start(struct peer *peer, mctp_eid_t eid_start,
				 uint8_t pool_size)
{
	uint8_t count = 0;
	mctp_eid_t pool_start = eid_alloc_max;
	struct net *n = lookup_net(peer->ctx, peer->net);

	if (!n) {
		warnx("BUG: Unknown net %d : failed to get pool start\n",
		      peer->net);
		return eid_alloc_max;
	}

	for (mctp_eid_t e = eid_start; e <= eid_alloc_max; e++) {
		if (n->peers[e] == NULL) {
			if (pool_start == eid_alloc_max) {
				pool_start = e;
			}
			count++;
			if (count == pool_size)
				return pool_start;
		} else {
			pool_start = eid_alloc_max;
			count = 0;
		}
	}

	return eid_alloc_max;
}

static int endpoint_allocate_eids(struct peer *peer)
{
	uint8_t allocated_pool_size = 0;
	mctp_eid_t allocated_pool_start = 0;
	int rc = 0;

	if (!mctp_eid_is_valid_unicast(peer->pool_start)) {
		warnx("Invalid pool start %d", peer->pool_start);
		return -1;
	}
	/* validate pool range is fully within [eid_alloc_min,
		* eid_alloc_max] before allocating to avoid landing on 0xFF. */
	if (peer->pool_size - 1 > (uint8_t)(eid_alloc_max - peer->pool_start)) {
		warnx("WARNING: bridge pool [%u..%u] out of allocatable range [%u..%u]; rejecting",
		      peer->pool_start, peer->pool_start + peer->pool_size - 1,
		      eid_alloc_min, eid_alloc_max);
		return -1;
	}
	/* Find pool sized contiguous unused eids to allocate on the bridge. */
	peer->pool_start =
		get_pool_start(peer, peer->pool_start, peer->pool_size);
	if (peer->pool_start == eid_alloc_max) {
		warnx("%s failed to find contiguous EIDs of required size",
		      __func__);
		return 0;
	} else {
		if (peer->ctx->verbose)
			fprintf(stderr,
				"%s Asking for contiguous EIDs for pool with start eid %d and size %d\n",
				__func__, peer->pool_start, peer->pool_size);
	}
	/* Add gateway route for all bridge's downstream EIDs.
	* After allocation, the endpoint may initiate communication
	* immediately, so set up routes for downstream endpoints beforehand.
	* Any EIDs in the ignore list are excluded; routes are installed
	* per-EID (extent 0) so late-discovered peers inside the range can
	* coexist without colliding with a range route.
	*/
	rc = add_pool_gw_routes_ignore_aware(peer);
	if (rc < 0 && rc != -EEXIST) {
		warnx("Failed to add gateway route for EID %d: %s", peer->eid,
		      strerror(-rc));
		int drc = del_pool_gw_routes_ignore_aware(peer);
		if (drc < 0)
			warnx("Rollback of partial pool gw routes failed: %s",
			      strerror(-drc));
		return rc;
	}

	rc = endpoint_send_allocate_endpoint_ids(
		peer, peer->pool_start, peer->pool_size,
		mctp_ctrl_cmd_allocate_eids_alloc_eids, &allocated_pool_size,
		&allocated_pool_start);
	if (rc) {
		warnx("%s failed to allocate endpoints, returned %s %d\n",
		      __func__, strerror(-rc), rc);
		// delete prior set routes for downstream endpoints
		rc = del_pool_gw_routes_ignore_aware(peer);
		if (rc < 0)
			warnx("failed to delete route for peer pool eids %d-%d %s",
			      peer->pool_start,
			      peer->pool_start + peer->pool_size - 1,
			      strerror(-rc));
		//reset peer pool
		peer->pool_size = 0;
		peer->pool_start = 0;
		return rc;
	} else {
		peer->pool_size = allocated_pool_size;
		peer->pool_start = allocated_pool_start;

		sd_bus_add_object_vtable(peer->ctx->bus, &peer->slot_bridge,
					 peer->path, CC_MCTP_DBUS_IFACE_BRIDGE,
					 bus_endpoint_bridge, peer);

		rc = sd_bus_emit_interfaces_added(peer->ctx->bus, peer->path,
						  CC_MCTP_DBUS_IFACE_BRIDGE,
						  NULL);
		if (rc < 0) {
			warnx("Failed to emit add %s signal for endpoint %d : %s",
			      CC_MCTP_DBUS_IFACE_BRIDGE, peer->eid,
			      strerror(-rc));
		}
		if (peer->ctx->verbose) {
			fprintf(stderr,
				"Bridge (eid %d) assigned pool [%d, %d], size %d\n",
				peer->eid, peer->pool_start,
				peer->pool_start + peer->pool_size - 1,
				peer->pool_size);
		}

		// Poll for downstream endpoint accessibility
		if (peer->ctx->endpoint_poll) {
			bridge_poll_start(peer);
		} else {
			//delay for settling MCTP Bridge after allocation of downstream eid
			uint64_t now_usec, timer_usec;
			// Get the current time in microseconds
			if (sd_event_now(peer->ctx->event, CLOCK_MONOTONIC,
					 &now_usec) < 0) {
				warnx("Failed to get current time");
				return -1;
			}
			timer_usec =
				now_usec + BRIDGE_SETTLE_DELAY_SEC * 1000000ULL;
			rc = sd_event_add_time(peer->ctx->event,
					       &peer->bridge_settle_timer,
					       CLOCK_MONOTONIC, timer_usec, 0,
					       cb_populate_pool_eids, peer);
			if (rc < 0) {
				warnx("Failed to add timer for bridge settle: %s",
				      strerror(-rc));
			}
		}
	}

	return 0;
}

static void update_local_routing(struct get_routing_table_entry **entry_routing,
				 struct get_routing_table_entry *rt_entry)
{
	size_t entry_size = sizeof(struct get_routing_table_entry) +
			    rt_entry->phys_address_size;

	struct get_routing_table_entry *entry = malloc(entry_size);
	if (!entry) {
		warnx("update_local_routing: malloc failed for size %zu",
		      entry_size);
		*entry_routing = NULL;
		return;
	}

	memcpy(entry, rt_entry, entry_size);
	*entry_routing = entry;
}

/* Get Routing Table data and update into local routing table */
static int
endpoint_send_get_routing_table(struct peer *peer, uint8_t entry_handle,
				uint8_t *next_handle, bool *active_pool_eid,
				struct get_routing_table_entry **local_routing)
{
	struct sockaddr_mctp_ext addr;
	struct mctp_ctrl_cmd_get_routing_table req;
	struct mctp_ctrl_resp_get_routing_table *resp = NULL;
	struct ctx *ctx = NULL;
	uint8_t *buf = NULL;
	size_t buf_size;
	uint8_t iid;
	int rc;

	iid = mctp_next_iid(peer->ctx);
	req.ctrl_hdr.rq_dgram_inst = RQDI_REQ | iid;
	req.ctrl_hdr.command_code = MCTP_CTRL_CMD_GET_ROUTING_TABLE_ENTRIES;
	req.entry_handle = entry_handle;
	ctx = peer->ctx;

	rc = endpoint_query_peer(peer, MCTP_CTRL_HDR_MSG_TYPE, &req,
				 sizeof(req), &buf, &buf_size, &addr);
	if (rc < 0)
		goto out;

	rc = mctp_ctrl_validate_get_routing_table_response(
		buf, buf_size, peer_tostr_short(peer), iid, &addr,
		peer->ping_failed_once);
	if (rc)
		goto out;

	resp = (void *)buf;
	if (!resp) {
		warnx("%s Invalid response Buffer\n", __func__);
		return -ENOMEM;
	}

	if (ctx->verbose) {
		fprintf(stderr,
			"%s: returned routing entries %x, next handle %x\n",
			__func__, resp->number_of_entries,
			resp->next_entry_handle);
	}

	*next_handle = resp->next_entry_handle;
	if (resp->number_of_entries) {
		struct get_routing_table_entry *entry =
			(struct get_routing_table_entry *)resp->routing_entries;
		for (uint8_t idx = 0; idx < resp->number_of_entries; idx++) {
			if ((entry->starting_eid == peer->eid) ||
			    (entry->starting_eid < peer->pool_start) ||
			    (entry->starting_eid >=
			     (peer->pool_start + peer->pool_size))) {
				// Skip bridge's own eid or any eid outside of the pool
				if (peer->ctx->verbose)
					fprintf(stderr, "skipping eid %d\n",
						entry->starting_eid);
				entry = (struct get_routing_table_entry *)
					routing_table_entry_next(entry);
				continue;
			}
			// Check if this EID should be ignored
			if (should_ignore_eid(peer, entry->starting_eid)) {
				if (ctx->verbose) {
					fprintf(stderr,
						"%s: ignoring EID %d as requested\n",
						__func__, entry->starting_eid);
				}
				entry = (struct get_routing_table_entry *)
					routing_table_entry_next(entry);
				continue;
			}

			if (entry->starting_eid >= peer->pool_start) {
				active_pool_eid[entry->starting_eid -
						peer->pool_start] = true;
			}

			update_local_routing(
				&local_routing[entry->starting_eid -
					       peer->pool_start],
				entry);

			entry = (struct get_routing_table_entry *)
				routing_table_entry_next(entry);
		}
	}

	/* need to free the buf as we are keeping copy inside local routing table */

out:
	free(buf);
	return rc;
}

static int query_routing_table(struct peer *peer)
{
	uint8_t next_handle = 0, entry_handle = 0;
	int net = peer->net;
	dest_phys dest = peer->phys;
	int rc = 0;
	//track active endpoints from Bridge perspective
	bool *active_pool_eid = NULL;
	struct get_routing_table_entry **local_routing = NULL;
	struct link *link =
		mctp_nl_get_link_userdata(peer->ctx->nl, peer->phys.ifindex);
	bool is_static_pool_bridge = false;
	const unsigned int max_iter = 256;
	unsigned int iter = 0;

	if (peer->pool_size == 0 &&
	    GET_ENDPOINT_TYPE(peer->endpoint_type) == MCTP_BUS_OWNER_BRIDGE) {
		// We don't know eid pool space for the Bridge (Static EID pool), need to rely on routing table data
		// temporary set pool size to eid_alloc_max and start to eid_alloc_min
		peer->pool_size = eid_alloc_max;
		peer->pool_start = eid_alloc_min;
		is_static_pool_bridge = true;
	}

	if (peer->pool_size) {
		active_pool_eid = (bool *)malloc(peer->pool_size);
		local_routing = (struct get_routing_table_entry **)malloc(
			peer->pool_size *
			sizeof(struct get_routing_table_entry *));
		if (active_pool_eid && local_routing) {
			for (uint8_t idx = 0; idx < peer->pool_size; idx++) {
				(active_pool_eid)[idx] = false;
				local_routing[idx] = NULL;
			}
		}
	} else {
		warnx(" %s Not a Bridge peer, pool size = %d", __func__,
		      peer->pool_size);
		return -1;
	}

	while (next_handle != 0xFF) {
		if (++iter > max_iter) {
			warnx("WARNING: %s pagination exceeded %u iterations; aborting",
			      __func__, max_iter);
			rc = -EPROTO;
			goto out;
		}
		rc = endpoint_send_get_routing_table(peer, entry_handle,
						     &next_handle,
						     active_pool_eid,
						     local_routing);
		if (rc < 0) {
			goto out;
		}
		if ((next_handle == 0 && entry_handle != 0) ||
		    (next_handle == entry_handle)) {
			warnx("Unexpected routing table entry handle 0 after %u iterations",
			      iter);
			rc = -ERANGE;
			goto out;
		}
		entry_handle = next_handle;
	}

	//Manage downstream endpoint objects based on active routing table
	if (active_pool_eid) {
		for (uint8_t index = 0; index < peer->pool_size; index++) {
			mctp_eid_t eid = index + peer->pool_start;
			struct peer *existing_peer =
				find_peer_by_addr(peer->ctx, eid, net);

			if (active_pool_eid[index]) {
				if (!existing_peer) {
					// EID is active but doesn't exist locally - create it
					struct peer *allocated_peer = NULL;
					rc = add_peer(peer->ctx, &dest, eid,
						      net, &allocated_peer,
						      true);
					if (rc < 0) {
						warnx("%s failed to add peer for active eid %d: %d %s",
						      __func__, eid, rc,
						      strerror(-rc));
						continue;
					}

					allocated_peer->routing_table_entry =
						local_routing[index];
					local_routing[index] = NULL;
					// Copy ignore message type for Bridge eid to its downstream eid
					if (peer->num_ignore_message_types >
					    0) {
						allocated_peer
							->num_ignore_message_types =
							peer->num_ignore_message_types;
						allocated_peer
							->ignore_message_types = malloc(
							peer->num_ignore_message_types);
						memcpy(allocated_peer
							       ->ignore_message_types,
						       peer->ignore_message_types,
						       peer->num_ignore_message_types);
					}
					if (is_static_pool_bridge) {
						peer->static_pool_eids[eid] =
							eid;
					}
					allocated_peer->pool_owner_eid =
						peer->eid;
					rc = setup_added_peer(allocated_peer);
					if (rc < 0) {
						warnx("%s failed to setup peer for active eid %d: %d %s",
						      __func__, eid, rc,
						      strerror(-rc));
						continue;
					}

					if (peer->ctx->verbose) {
						fprintf(stderr,
							"created new endpoint %d\n",
							eid);
					}
				} else {
					// EID is active and exists locally - send connectivity change
					existing_peer->degraded = false;
					//to fetch latest UUID/MessageType
					rc = query_peer_properties(
						existing_peer);
					if (rc < 0)
						warnx("%s: query_peer_properties failed: %d %s",
						      __func__, rc,
						      strerror(-rc));

					const char *peer_path =
						path_from_peer(existing_peer);
					if (!peer_path) {
						warnx("%s: no path to peer exists",
						      __func__);
						continue;
					}
					rc = sd_bus_emit_properties_changed(
						peer->ctx->bus, peer_path,
						CC_MCTP_DBUS_IFACE_ENDPOINT,
						"Connectivity", NULL);
					if (rc < 0) {
						warnx("%s: Connectivity change emit failed: %d %s",
						      __func__, rc,
						      strerror(-rc));
						continue;
					}
					if (peer->ctx->verbose) {
						fprintf(stderr,
							"keeping existing active endpoint %d\n",
							eid);
					}
					//TODO: should we update the rounting entry for this eid as well?
				}
			} else {
				if ((existing_peer &&
				     false == should_ignore_eid(peer, eid) &&
				     !is_static_pool_bridge) ||
				    (existing_peer && is_static_pool_bridge &&
				     peer->static_pool_eids[eid] == eid)) {
					// EID is not active but exists locally - remove it
					if (!existing_peer->degraded) {
						if (peer->ctx->verbose) {
							fprintf(stderr,
								"inactive endpoint, removing %d\n",
								eid);
						}
						rc = remove_peer(existing_peer);
						if (rc < 0) {
							warnx("Failed to remove endpoint %d : %s",
							      eid,
							      strerror(rc));
						}
					}
				}
			}
		}
	}
	// clean all thats left behind as peer might already have routing entry
	for (uint8_t idx = 0; idx < peer->pool_size; idx++) {
		free(local_routing[idx]);
	}
	free(local_routing);
	free(active_pool_eid);

	// Set service state to Enabled for bridge endpoints after routing table processing
	if (link && link->service_state == SERVICE_STATE_STARTING) {
		link->service_state = SERVICE_STATE_ENABLED;
		rc = sd_bus_emit_properties_changed(
			peer->ctx->bus, link->path,
			OPENBMC_SERVICE_READINESS_IFACE, "State", NULL);
		if (rc < 0) {
			warnx("%s: Service state change emit failed: %d %s",
			      __func__, rc, strerror(-rc));
		}
	}

	// Restore pool size and start to original values
	if (peer->pool_size == eid_alloc_max &&
	    peer->pool_start == eid_alloc_min) {
		peer->pool_size = 0;
		peer->pool_start = 0;
	}
	return 0;
out:
	for (uint8_t idx = 0; idx < peer->pool_size; idx++) {
		free(local_routing[idx]);
	}
	free(local_routing);
	free(active_pool_eid);
	warnx(" %s Failed to get routing table data for handle %d\n", __func__,
	      entry_handle);
	// Restore pool size and start to original values
	if (peer->pool_size == eid_alloc_max &&
	    peer->pool_start == eid_alloc_min) {
		peer->pool_size = 0;
		peer->pool_start = 0;
	}
	return rc;
}

static bool should_ignore_eid(const struct peer *peer, mctp_eid_t eid)
{
	// Check if BMC as Bridge is enabled
	if (peer->ctx->bmc_bridge_eid) {
		for (size_t i = 0; i < peer->ctx->bmc_ignore_eids_count; i++) {
			if (peer->ctx->bmc_ignore_eids[i] == eid)
				return true;
		}
	}

	if (!peer->ignore_eids)
		return false;

	for (size_t i = 0; i < peer->num_ignore_eids; i++) {
		if (peer->ignore_eids[i] == eid)
			return true;
	}

	return false;
}

/*
 * Walk the bridge peer's downstream pool [pool_start .. pool_start+pool_size-1]
 * and install (or remove) a separate gateway route per EID, skipping any EID
 * flagged by should_ignore_eid(). The peer's own EID/net is used as the
 * gateway. extent is 0 on every call so each route covers exactly one EID.
 *
 * Per-EID (rather than range) routes are used so that late-discovered peers
 * inside the pool range don't collide with an existing range route — the
 * kernel rejects single-EID adds that overlap a range with -EEXIST.
 *
 * On add, -EEXIST is tolerated (an existing route for that EID is left in
 * place). On delete, errors are logged but iteration continues so as many
 * EIDs as possible are cleaned up; the first error is returned.
 */
static int walk_pool_gw_routes(struct peer *peer, bool adding)
{
	if (peer->pool_size == 0)
		return 0;

	struct mctp_fq_addr gw_addr = { 0 };
	gw_addr.net = peer->net;
	gw_addr.eid = peer->eid;

	const int pool_end = peer->pool_start + peer->pool_size - 1;
	int first_err = 0;

	for (int eid = peer->pool_start; eid <= pool_end; eid++) {
		if (should_ignore_eid(peer, (mctp_eid_t)eid))
			continue;

		int rc;
		if (adding) {
			rc = mctp_nl_route_add(peer->ctx->nl, (uint8_t)eid, 0,
					       0, &gw_addr, peer->mtu);
			if (rc < 0 && rc != -EEXIST) {
				warnx("Failed to add gateway route for EID %d via %d: %s",
				      eid, gw_addr.eid, strerror(-rc));
				return rc;
			}
		} else {
			rc = mctp_nl_route_del(peer->ctx->nl, (uint8_t)eid, 0,
					       0, &gw_addr);
			if (rc < 0) {
				warnx("Failed to delete gateway route for EID %d via %d: %s",
				      eid, gw_addr.eid, strerror(-rc));
				if (!first_err)
					first_err = rc;
			}
		}
		if (peer->ctx->verbose)
			fprintf(stderr,
				"%s gateway route EID %d via %d (net %d)\n",
				adding ? "added" : "deleted", eid, gw_addr.eid,
				gw_addr.net);
	}

	return first_err;
}

static int add_pool_gw_routes_ignore_aware(struct peer *peer)
{
	return walk_pool_gw_routes(peer, true);
}

static int del_pool_gw_routes_ignore_aware(struct peer *peer)
{
	return walk_pool_gw_routes(peer, false);
}

static int endpoint_send_routing_info_update(struct peer *peer,
					     mctp_eid_t first_eid,
					     uint8_t range, uint8_t entry_type,
					     uint8_t phy_addr_size,
					     uint8_t *phy_addr)
{
	size_t entry_size = routing_info_entry_size_from_phys(phy_addr_size);
	struct routing_info_entry *e = NULL;
	struct mctp_ctrl_resp *resp = NULL;
	struct mctp_ctrl_cmd_routing_info_update *req = NULL;
	struct sockaddr_mctp_ext addr;
	uint8_t *buf = NULL;
	size_t buf_size;
	uint8_t iid;
	int rc;
	size_t req_len;

	rc = 0;
	iid = mctp_next_iid(peer->ctx);

	e = (struct routing_info_entry *)malloc(entry_size);
	if (!e) {
		rc = -ENOMEM;
		goto out;
	}

	e->entry_type = 0;
	e->eid_range = range;
	e->first_eid = first_eid;

	if (phy_addr_size > 0 && phy_addr)
		memcpy(e->phys_address, phy_addr, phy_addr_size);

	req_len = sizeof(struct mctp_ctrl_cmd_routing_info_update) - 1 +
		  entry_size;
	req = (struct mctp_ctrl_cmd_routing_info_update *)malloc(req_len);
	if (!req) {
		rc = -ENOMEM;
		goto out;
	}
	mctp_ctrl_msg_hdr_init_req(&req->ctrl_hdr, iid,
				   MCTP_CTRL_CMD_ROUTING_INFO_UPDATE);
	req->number_of_entries = 1;

	memcpy(req->entries, e, entry_size);

	rc = endpoint_query_peer(peer, MCTP_CTRL_HDR_MSG_TYPE, req, req_len,
				 &buf, &buf_size, &addr);
	if (rc < 0)
		goto out;

	rc = mctp_ctrl_validate_completion_response(
		buf, buf_size, peer_tostr_short(peer), iid,
		MCTP_CTRL_CMD_ROUTING_INFO_UPDATE, &addr,
		peer->ping_failed_once);
	if (rc)
		goto out;

	resp = (void *)buf;
	if (resp->completion_code != MCTP_CTRL_CC_SUCCESS) {
		warnx("Failed to upate routing entry [Comp Code :: %x]",
		      resp->completion_code);
	}

out:
	free(buf);
	free(req);
	free(e);
	return rc;
}

int main(int argc, char **argv)
{
	struct ctx ctxi = { 0 }, *ctx = &ctxi;
	int rc;

	setlinebuf(stdout);
	setlinebuf(stderr);

	setup_config_defaults(ctx);
	setup_ctrl_cmd_defaults(ctx);

	mctp_ops_init();
	rc = parse_args(ctx, argc, argv);
	if (rc != 0) {
		return rc;
	}

	rc = parse_config(ctx);
	if (rc) {
		err(EXIT_FAILURE, "Can't read configuration");
	}

	ctx->nl = mctp_nl_new(false);
	if (!ctx->nl) {
		warnx("Failed creating netlink object");
		return 1;
	}
	mctp_nl_warn_eexist(ctx->nl, false);

	/* D-Bus needs to be set up before setup_nets() so we
	   can populate D-Bus objects for interfaces */
	rc = setup_bus(ctx);
	if (rc < 0) {
		warnx("Error in setup, returned %s %d", strerror(-rc), rc);
		return 1;
	}

	/* Listen prior to setup_nets() so we don't miss any updates */
	rc = listen_monitor(ctx);
	if (rc < 0) {
		warnx("Error monitoring netlink updates. State changes will be ignored. (%s)",
		      strerror(-rc));
	}

	rc = setup_nets(ctx);
	if (rc < 0)
		return 1;

	// TODO add net argument?
	rc = listen_control_msg(ctx, MCTP_NET_ANY);
	if (rc < 0) {
		warnx("Error in listen, returned %s %d", strerror(-rc), rc);
		return 1;
	}

	// All setup must be complete by here, we might immediately
	// get requests from waiting clients.
	rc = request_dbus(ctx);
	if (rc < 0)
		return 1;

	rc = sd_event_loop(ctx->event);
	sd_event_unref(ctx->event);
	if (rc < 0) {
		warnx("Error in loop, returned %s %d", strerror(-rc), rc);
		return 1;
	}

	sd_bus_flush_close_unrefp(&ctx->bus);

	free_links(ctx);
	free_peers(ctx);
	free_nets(ctx);
	free_config(ctx);
	free_ctrl_cmd_defaults(ctx);

	mctp_nl_close(ctx->nl);

	return 0;
}
