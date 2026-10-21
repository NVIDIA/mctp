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

#define _GNU_SOURCE
#include "config.h"

#include <assert.h>
#include <err.h>
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>

#include "mctpd-internal.h"

static int op_validate_response(struct pending_op *op, uint8_t *resp,
				size_t resp_len,
				const struct sockaddr_mctp_ext *resp_addr,
				size_t exp_size, const char *peer_str,
				uint8_t cmd_id);


/* Deferred-completion state machine for the endpoint-lifecycle D-Bus
 * methods (SetupEndpoint, AssignEndpoint, AssignEndpointStatic and
 * LearnEndpoint). Each call is tracked by a struct pending_op holding the
 * inbound message, the io/timer event sources, a caller-disconnect
 * tracker and the current step. Every exit path goes through
 * pending_op_cleanup(). */

/* enum op_kind, enum op_step and op_step_cb_t are forward-declared at
 * the top of this file alongside the rest of the deferred-completion
 * forward declarations. */


/* ---------------- field setters --------------------------------- */

void pending_op_set_peer(struct pending_op *op, struct peer *peer)
{
	op->peer = peer;
	op->is_dummy = true;
}

void pending_op_set_static_args(
	struct pending_op *op, mctp_eid_t static_eid, uint8_t static_pool_start,
	const uint8_t *ignore_eids, size_t ignore_eids_len,
	const uint8_t *ignore_message_types, size_t ignore_message_types_len)
{
	op->static_eid = static_eid;
	op->static_pool_start = static_pool_start;
	op->ignore_eids = ignore_eids;
	op->ignore_eids_len = ignore_eids_len;
	op->ignore_message_types = ignore_message_types;
	op->ignore_message_types_len = ignore_message_types_len;
}

/* ---------------- in_flight index helpers ---------------------- */

struct in_flight_node *in_flight_find(struct ctx *ctx, uint32_t net_id,
					     const uint8_t *hwaddr,
					     uint8_t hwaddr_len, int ifindex)
{
	struct in_flight_node *node;

	for (node = ctx->in_flight_ops; node; node = node->next) {
		if (node->net_id != net_id)
			continue;
		if (node->hwaddr_len != hwaddr_len)
			continue;
		/* Interface1 calls scope by ifindex; Network1 calls leave
		 * ifindex == 0 and accept any match on net_id+hwaddr. */
		if (ifindex && node->ifindex && node->ifindex != ifindex)
			continue;
		if (hwaddr_len == 0 ||
		    memcmp(node->hwaddr, hwaddr, hwaddr_len) == 0)
			return node;
	}
	return NULL;
}

int in_flight_register(struct ctx *ctx, struct pending_op *op,
			      uint32_t net_id, int ifindex)
{
	struct in_flight_node *node;

	node = calloc(1, sizeof(*node));
	if (!node)
		return -ENOMEM;

	node->net_id = net_id;
	node->ifindex = ifindex;
	node->hwaddr_len = (uint8_t)op->dest.hwaddr_len;
	if (op->dest.hwaddr_len)
		memcpy(node->hwaddr, op->dest.hwaddr, op->dest.hwaddr_len);
	node->op = op;
	node->next = ctx->in_flight_ops;
	ctx->in_flight_ops = node;
	op->in_flight_node = node;
	return 0;
}

static void in_flight_unregister(struct ctx *ctx, struct pending_op *op)
{
	struct in_flight_node **pp;

	if (!op->in_flight_node)
		return;

	for (pp = &ctx->in_flight_ops; *pp; pp = &(*pp)->next) {
		if (*pp == op->in_flight_node) {
			*pp = (*pp)->next;
			break;
		}
	}
	free(op->in_flight_node);
	op->in_flight_node = NULL;
}

/* ---------------- pending_op cleanup + reply helpers ----------- */

/* Fire-and-forget Routing Info Update to downstream bridges. Each bridge
 * gets its own synthetic pending_op (call == NULL); riu_done logs the
 * result and cleans up. No peer state is mutated. */
static void riu_done(struct pending_op *op, int rc,
		     uint8_t *resp, size_t resp_len,
		     const struct sockaddr_mctp_ext *resp_addr)
{
	mctp_eid_t bridge_eid = op->peer ? op->peer->eid : 0;
	mctp_eid_t first_eid = op->static_eid;
	(void)resp_addr;

	if (rc == 0)
		rc = op_validate_response(op, resp, resp_len, resp_addr,
					  sizeof(struct mctp_ctrl_resp),
					  op->peer ? peer_tostr_short(op->peer) :
						     "bridge",
					  MCTP_CTRL_CMD_ROUTING_INFO_UPDATE);
	if (rc < 0) {
		warnx("async RIU to bridge eid %d for eid %d failed: %s",
		      bridge_eid, first_eid, strerror(-rc));
	} else if (op->ctx->verbose) {
		warnx("async RIU to bridge eid %d for eid %d: ok", bridge_eid,
		      first_eid);
	}
	free(resp);
	pending_op_cleanup(op);
}

static void riu_send_async(struct ctx *ctx, struct peer *bridge,
			   mctp_eid_t first_eid, uint8_t eid_range,
			   uint8_t entry_type)
{
	struct routing_info_entry *e;
	size_t entry_size = sizeof(struct routing_info_entry) - 1;
	size_t req_len =
		sizeof(struct mctp_ctrl_cmd_routing_info_update) - 1 + entry_size;
	struct mctp_ctrl_cmd_routing_info_update *req;
	struct pending_op *op;
	int rc;

	op = calloc(1, sizeof(*op));
	if (!op) {
		warnx("riu_send_async: OOM for bridge eid %d", bridge->eid);
		return;
	}
	op->ctx = ctx;
	op->call = NULL; /* synthetic — no D-Bus reply */
	op->kind = OP_ROUTING_INFO_UPDATE;
	op->peer = bridge;
	op->static_eid = first_eid; /* carries target EID for logging in riu_done */
	op->dest = bridge->phys;
	op->sock_fd = -1;

	req = malloc(req_len);
	if (!req) {
		warnx("riu_send_async: OOM req for bridge eid %d", bridge->eid);
		free(op);
		return;
	}
	mctp_ctrl_msg_hdr_init_req(&req->ctrl_hdr, mctp_next_iid(ctx),
				   MCTP_CTRL_CMD_ROUTING_INFO_UPDATE);
	req->number_of_entries = 1;
	e = (struct routing_info_entry *)req->entries;
	e->entry_type = entry_type;
	e->eid_range = eid_range;
	e->first_eid = first_eid;

	rc = pending_op_launch_step_eid(op, bridge->eid, bridge->net,
					STEP_ROUTING_INFO_UPDATE,
					req, req_len, riu_done);
	free(req);
	if (rc < 0) {
		warnx("riu_send_async: launch failed for bridge eid %d: %s",
		      bridge->eid, strerror(-rc));
		pending_op_cleanup(op);
	}
}

void schedule_riu_to_bridges(struct ctx *ctx, mctp_eid_t first_eid,
				    uint8_t eid_range, uint8_t entry_type)
{
	for (size_t i = 0; i < ctx->num_peers; i++) {
		struct peer *peer = ctx->peers[i];
		if (GET_ENDPOINT_TYPE(peer->endpoint_type) != MCTP_BUS_OWNER_BRIDGE)
			continue;
		riu_send_async(ctx, peer, first_eid, eid_range, entry_type);
	}
}

/* sd_bus_reply_method_*() does not consume the caller's reference on the
 * call message, so drop the one taken in pending_op_begin() after replying. */
static void pending_op_release_call(struct pending_op *op)
{
	sd_bus_message_unref(op->call);
	op->call = NULL;
}

/* Single cleanup sink. Every exit path (success reply, error reply,
 * timeout, IO error, caller disconnect, setup failure) must pass
 * through this function exactly once. */
void pending_op_cleanup(struct pending_op *op)
{
	struct peer *dummy_peer = NULL;

	if (!op)
		return;

	/* The peer created for this op. While pool finalize is running,
	 * op->peer is the downstream peer being queried and the op's own peer
	 * (the bridge) is parked in finalize_saved_peer. */
	if (op->is_dummy)
		dummy_peer = op->finalize_active ? op->finalize_saved_peer :
						   op->peer;

	if (op->io_src) {
		sd_event_source_disable_unref(op->io_src);
		op->io_src = NULL;
	}
	if (op->tm_src) {
		sd_event_source_disable_unref(op->tm_src);
		op->tm_src = NULL;
	}
	if (op->sock_fd >= 0) {
		close(op->sock_fd);
		op->sock_fd = -1;
	}
	if (op->caller_track) {
		sd_bus_track_unref(op->caller_track);
		op->caller_track = NULL;
	}
	if (op->in_flight_node)
		in_flight_unregister(op->ctx, op);

	/* Routing-table fragment-loop accumulation buffers, if the op is
	 * torn down mid-loop (caller disconnect / error before finalize). */
	if (op->rt_local_routing) {
		struct peer *rtp = op->rt_pool_peer;
		if (rtp) {
			for (uint8_t idx = 0; idx < rtp->pool_size; idx++)
				free(op->rt_local_routing[idx]);
		}
		free(op->rt_local_routing);
		op->rt_local_routing = NULL;
		/* Undo the temporary static-pool sizing from
		 * routing_table_loop_start(). */
		if (rtp && rtp != dummy_peer && op->rt_is_static_pool_bridge &&
		    rtp->pool_start == eid_alloc_min) {
			rtp->pool_size = 0;
			rtp->pool_start = 0;
		}
	}
	if (op->rt_active_pool_eid) {
		free(op->rt_active_pool_eid);
		op->rt_active_pool_eid = NULL;
	}

	/* Pool-finalize accumulator buffers, if torn down mid-loop
	 * (caller disconnect / error before rt_finalize_pool_complete). */
	if (op->finalize_routing) {
		for (uint8_t idx = 0; idx < op->finalize_pool_size; idx++)
			free(op->finalize_routing[idx]);
		free(op->finalize_routing);
		op->finalize_routing = NULL;
	}
	if (op->finalize_active) {
		struct peer *fb = op->finalize_bridge;

		if (fb && fb != dummy_peer && op->finalize_static_pool &&
		    fb->pool_start == eid_alloc_min) {
			fb->pool_size = 0;
			fb->pool_start = 0;
		}
		free(op->finalize_active);
		op->finalize_active = NULL;
	}

	/* Deferred-send request copy, if torn down mid-send. */
	if (op->send_buf) {
		free(op->send_buf);
		op->send_buf = NULL;
	}

	/* Per-step request copy and any partially collected VDM sets. */
	free(op->step_req);
	op->step_req = NULL;
	free(op->qpp_vdm_types);
	op->qpp_vdm_types = NULL;

	/* Peer created just for this op (Learn-fail, Setup-pre-EID-failure,
	 * or an Assign abandoned part-way). Removing a bridge also removes
	 * its pool members, so a bridge that is itself being removed keeps
	 * its temporary pool range above. */
	if (dummy_peer)
		remove_peer(dummy_peer);
	op->peer = NULL;

	/* Held inbound message — sd_bus_reply_*() takes ownership in
	 * the success/error reply paths and the helper below clears
	 * op->call before reaching here. This catches the no-reply
	 * paths (caller disconnect, cleanup before any reply). */
	if (op->call) {
		sd_bus_message_unref(op->call);
		op->call = NULL;
	}

	free(op);
}

/* sd_bus_track disconnect callback. Caller went away before we
 * emitted the deferred reply — abandon the op silently. */
static int on_caller_gone(sd_bus_track *track, void *userdata)
{
	struct pending_op *op = userdata;

	if (op->ctx->verbose)
		warnx("caller gone, abandoning pending op kind=%d", op->kind);

	pending_op_cleanup(op);
	return 0;
}

static void pending_op_reply_error(struct pending_op *op, int rc)
{
	sd_bus_error berr = SD_BUS_ERROR_NULL;

	/* Synthetic ops (non-dispatch callers) have no held call to
	 * reply on — just clean up. */
	if (!op->call) {
		pending_op_cleanup(op);
		return;
	}

	set_berr(op->ctx, rc, &berr);
	sd_bus_reply_method_error(op->call, &berr);
	sd_bus_error_free(&berr);
	pending_op_release_call(op);
	pending_op_cleanup(op);
}

static void pending_op_reply_success(struct pending_op *op,
				     const char *peer_path, uint8_t new_flag)
{
	if (!op->call) {
		pending_op_cleanup(op);
		return;
	}

	if (op->peer) {
		sd_bus_reply_method_return(op->call, "yisb", op->peer->eid,
					   op->peer->net, peer_path, new_flag);
	} else {
		/* Defensive: should not normally happen for the success
		 * path; preserve baseline shape of replying with zeroed
		 * EID/net (matches method_learn_endpoint's not-found
		 * synchronous fast-path semantics). */
		sd_bus_reply_method_return(op->call, "yisb", (uint8_t)0,
					   (int32_t)0, "", new_flag);
	}
	pending_op_release_call(op);
	pending_op_cleanup(op);
}

/* ---------------- shared step launcher and completion ---------- */

static int cb_op_io(sd_event_source *s, int fd, uint32_t revents, void *data);
static int cb_op_timeout(sd_event_source *s, uint64_t usec, void *data);
static int cb_op_send(sd_event_source *s, int fd, uint32_t revents, void *data);
static int step_send(struct pending_op *op);
static int op_validate_response(struct pending_op *op, uint8_t *resp,
				size_t resp_len,
				const struct sockaddr_mctp_ext *resp_addr,
				size_t exp_size, const char *peer_str,
				uint8_t cmd_id);
static void op_report_discovery_failure(
	struct pending_op *op, int ifindex, uint8_t cmd_code, mctp_eid_t eid,
	int rc, const uint8_t *resp, size_t resp_len,
	const struct sockaddr_mctp_ext *resp_addr, const char *reason);

/* Maximum number of transmissions of one step's request before the step
 * fails with -ETIMEDOUT. Mirrors endpoint_query_addr()'s retry loop
 * (max_retries = 2, or 1 with disable_retry): a retransmission reuses the
 * same request bytes and thus the same IID (DSP0237 Table 9). */
#define STEP_MAX_ATTEMPTS 2

/* Set the reporting / retry policy of the step about to be launched.
 * discovery: report failure once through DiscoveryCommandFailed instead
 * of TransportError. no_retry: do not retransmit on timeout. */
void pending_op_set_step_policy(struct pending_op *op, bool discovery,
				bool no_retry)
{
	op->step_discovery = discovery;
	op->step_no_retry = no_retry;
}

static void pending_op_step_complete(struct pending_op *op, int rc,
				     uint8_t *resp, size_t resp_len,
				     const struct sockaddr_mctp_ext *resp_addr)
{
	op_step_cb_t cb;

	if (op->io_src) {
		sd_event_source_disable_unref(op->io_src);
		op->io_src = NULL;
	}
	if (op->tm_src) {
		sd_event_source_disable_unref(op->tm_src);
		op->tm_src = NULL;
	}
	if (op->sock_fd >= 0) {
		close(op->sock_fd);
		op->sock_fd = -1;
	}

	/* Clear the error-streak flag on a successful step so the next
	 * failure for this peer logs again (mirrors pending_ping_reply_success). */
	if (rc == 0 && op->peer)
		op->peer->ping_failed_once = false;

	cb = op->step_cb;
	op->step_cb = NULL;
	if (cb) {
		/* Ownership of `resp` transfers into the continuation;
		 * it must free(resp). */
		cb(op, rc, resp, resp_len, resp_addr);
	} else {
		free(resp);
		pending_op_reply_error(op, -EPROTO);
	}
}

/* Open a socket, send the request, register io + timer event sources.
 * On any setup failure returns negative without registering anything,
 * so the caller can take the synchronous-error-reply rollback path. */
static int start_step(struct pending_op *op, enum op_step next_step,
		      uint8_t mctp_msg_type, const void *req, size_t req_len,
		      const struct sockaddr_mctp_ext *dest_addr, bool ext_addr,
		      op_step_cb_t step_cb)
{
	uint8_t *copy;

	(void)mctp_msg_type; /* msg type is embedded in dest_addr already */

	op->step = next_step;
	op->step_cb = step_cb;
	op->req_addr = *dest_addr;
	op->step_ext_addr = ext_addr;
	op->step_attempt = 1;
	op->step_fail_stage = MCTP_CTRL_CMD_FAIL_NONE;
	/* Snapshot the log-suppression state at step start, as the sync
	 * helpers do (cmd.suppress_logs = peer->ping_failed_once): the
	 * timeout path sets ping_failed_once before the continuation runs. */
	op->step_suppress = op->peer && op->peer->ping_failed_once;

	/* Keep a copy of the request for retransmission and for the
	 * TransportError / DiscoveryCommandFailed command attribution. */
	copy = malloc(req_len ? req_len : 1);
	if (!copy) {
		op->step_cb = NULL;
		op->step = STEP_NONE;
		return -ENOMEM;
	}
	memcpy(copy, req, req_len);
	free(op->step_req);
	op->step_req = copy;
	op->step_req_len = req_len;

	/* Snapshot the request IID so the response can be matched in
	 * cb_op_io. The request payload begins with a struct
	 * mctp_ctrl_msg_hdr — the low 5 bits of the first byte
	 * (rq_dgram_inst) carry the IID. */
	if (req_len >= 1) {
		op->iid = ((const uint8_t *)req)[0] & RQDI_IID_MASK;
		op->cmd_code = req_len >= 2 ? ((const uint8_t *)req)[1] : 0xFF;
	} else {
		op->iid = 0;
		op->cmd_code = 0xFF;
	}

	return step_send(op);
}

/* Open a socket, (re)send op->step_req, register io + timer event
 * sources. Shared by the first transmission (start_step) and the same-IID
 * retransmission on timeout (cb_op_timeout). On any setup failure returns
 * negative without registering anything. */
static int step_send(struct pending_op *op)
{
	struct ctx *ctx = op->ctx;
	const struct sockaddr_mctp_ext *dest_addr = &op->req_addr;
	const uint8_t *req = op->step_req;
	size_t req_len = op->step_req_len;
	bool ext_addr = op->step_ext_addr;
	size_t dest_addr_len;
	int sd = -1, val;
	int rc;

	sd = mctp_ops.mctp.socket();
	if (sd < 0) {
		rc = -errno;
		if (ctx->verbose)
			warnx("%s: socket() failed: %s", __func__,
			      strerror(-rc));
		goto setup_fail;
	}

	val = 1;
	rc = mctp_ops.mctp.setsockopt(sd, SOL_MCTP, MCTP_OPT_ADDR_EXT, &val,
				      sizeof(val));
	if (rc < 0) {
		rc = -errno;
		warnx("%s: kernel does not support MCTP extended addressing: %s",
		      __func__, strerror(-rc));
		goto setup_fail;
	}

	val = 1;
	rc = mctp_ops.mctp.setsockopt(sd, SOL_MCTP, MCTP_OPT_ENABLE_ERRQUEUE,
				      &val, sizeof(val));
	if (rc < 0) {
		if (ctx->verbose)
			warnx("%s: MCTP error queue not supported by kernel (fd %d)",
			      __func__, sd);
		/* non-fatal */
	}

	/* Non-blocking so a full TX buffer yields EAGAIN rather than
	 * stalling the event loop; cb_op_send finishes the send. */
	{
		int fl = fcntl(sd, F_GETFL, 0);

		if (fl < 0 || fcntl(sd, F_SETFL, fl | O_NONBLOCK) < 0) {
			rc = -errno;
			goto setup_fail;
		}
	}

	dest_addr_len = ext_addr ? sizeof(struct sockaddr_mctp_ext) :
				   sizeof(struct sockaddr_mctp);

	op->sock_fd = sd;

	rc = mctp_ops.mctp.sendto(sd, req, req_len, 0,
				  (struct sockaddr *)dest_addr, dest_addr_len);
	if (rc < 0) {
		rc = -errno;
		if (rc == -EAGAIN || rc == -EWOULDBLOCK) {
			/* TX buffer full: copy the request (req may be on the
			 * stack) and defer the send to cb_op_send. */
			op->send_buf = malloc(req_len);
			if (!op->send_buf) {
				rc = -ENOMEM;
				goto setup_fail;
			}
			memcpy(op->send_buf, req, req_len);
			op->send_len = req_len;
			op->send_off = 0;
			op->send_addr = *dest_addr;
			op->send_ext_addr = ext_addr;
			rc = sd_event_add_io(ctx->event, &op->io_src, sd,
					     EPOLLOUT | EPOLLERR, cb_op_send, op);
			if (rc < 0) {
				warnx("%s: sd_event_add_io (EPOLLOUT) failed: %s",
				      __func__, strerror(-rc));
				goto setup_fail;
			}
			goto arm_timer;
		}
		op->step_fail_stage = MCTP_CTRL_CMD_FAIL_SEND;
		{
			mctp_eid_t eid =
				dest_addr->smctp_base.smctp_addr.s_addr;
			if (!op->step_suppress) {
				warnx("%s: sendto cmd %s (0x%02x) to eid %d failed: %s",
				      __func__, command_str(op->cmd_code),
				      op->cmd_code, eid, strerror(-rc));
				/* Synthesize a TX error and emit TransportError,
				 * unless the continuation reports the failure
				 * through DiscoveryCommandFailed. */
				if (!op->step_discovery)
					report_transaction_error(ctx, -rc,
								 MCTP_DIR_TX,
								 dest_addr, req,
								 req_len);
				if (op->peer)
					op->peer->ping_failed_once = true;
			}
		}
		goto setup_fail;
	}
	if ((size_t)rc != req_len) {
		/* Partial datagram accepted. AF_MCTP datagrams are atomic so this
		 * is defensive, but finish the remainder via the EPOLLOUT
		 * sub-state rather than failing the transaction. */
		op->send_buf = malloc(req_len);
		if (!op->send_buf) {
			rc = -ENOMEM;
			goto setup_fail;
		}
		memcpy(op->send_buf, req, req_len);
		op->send_len = req_len;
		op->send_off = (size_t)rc;
		op->send_addr = *dest_addr;
		op->send_ext_addr = ext_addr;
		rc = sd_event_add_io(ctx->event, &op->io_src, sd,
				     EPOLLOUT | EPOLLERR, cb_op_send, op);
		if (rc < 0) {
			warnx("%s: sd_event_add_io (EPOLLOUT) failed: %s",
			      __func__, strerror(-rc));
			goto setup_fail;
		}
		goto arm_timer;
	}

	rc = sd_event_add_io(ctx->event, &op->io_src, sd, EPOLLIN | EPOLLERR,
			     cb_op_io, op);
	if (rc < 0) {
		warnx("%s: sd_event_add_io failed: %s", __func__,
		      strerror(-rc));
		goto setup_fail;
	}

arm_timer:
	/* Step timeout is ctx->mctp_timeout (microseconds). Recovery ops
	 * register it through mctp_ops.sd_event so the unit-test mock clock
	 * can gate the poll loop; in production this is
	 * sd_event_add_time_relative(). Other ops call it directly. */
	if (op->kind == OP_RECOVER)
		rc = mctp_ops.sd_event.add_time_relative(
			ctx->event, &op->tm_src, CLOCK_MONOTONIC,
			ctx->mctp_timeout, 0, cb_op_timeout, op);
	else
		rc = sd_event_add_time_relative(ctx->event, &op->tm_src,
						CLOCK_MONOTONIC,
						ctx->mctp_timeout, 0,
						cb_op_timeout, op);
	if (rc < 0) {
		warnx("%s: sd_event_add_time_relative failed: %s", __func__,
		      strerror(-rc));
		goto setup_fail;
	}

	return 0;

setup_fail:
	if (op->io_src) {
		sd_event_source_disable_unref(op->io_src);
		op->io_src = NULL;
	}
	if (op->sock_fd >= 0) {
		close(op->sock_fd);
		op->sock_fd = -1;
	} else if (sd >= 0) {
		close(sd);
	}
	/* Drop any stashed deferred-send request. */
	if (op->send_buf) {
		free(op->send_buf);
		op->send_buf = NULL;
	}
	op->step_cb = NULL;
	op->step = STEP_NONE;
	return rc;
}

static int cb_op_io(sd_event_source *s, int fd, uint32_t revents, void *data)
{
	struct pending_op *op = data;
	uint8_t *resp = NULL;
	size_t resp_len = 0;
	struct sockaddr_mctp_ext resp_addr = { 0 };
	int rc;

	if (revents & EPOLLERR) {
		read_mctp_error_queue(op->ctx, fd, op->ctx->verbose,
				      &op->req_addr, op->step_req,
				      op->step_req_len, !op->step_discovery);
		if (!(revents & EPOLLIN)) {
			op->step_fail_stage = MCTP_CTRL_CMD_FAIL_RECV;
			pending_op_step_complete(op, -EIO, NULL, 0, NULL);
			return 0;
		}
	}

	if (revents & EPOLLIN) {
		rc = read_message(op->ctx, fd, &resp, &resp_len, &resp_addr,
				  op->step_suppress);
		if (rc < 0) {
			free(resp);
			op->step_fail_stage = MCTP_CTRL_CMD_FAIL_RECV;
			pending_op_step_complete(op, rc, NULL, 0, NULL);
			return 0;
		}
		if (resp_addr.smctp_base.smctp_type !=
		    op->req_addr.smctp_base.smctp_type) {
			if (op->ctx->verbose)
				warnx("%s: mismatching response type %d for request type %d",
				      __func__, resp_addr.smctp_base.smctp_type,
				      op->req_addr.smctp_base.smctp_type);
			free(resp);
			pending_op_step_complete(op, -ENOMSG, NULL, 0, NULL);
			return 0;
		}
		/* Drop responses whose IID doesn't match the request;
		 * unrelated or delayed responses must not reach the
		 * continuation. */
		if (resp_len >= sizeof(struct mctp_ctrl_msg_hdr) &&
		    op->req_addr.smctp_base.smctp_type ==
			    MCTP_CTRL_HDR_MSG_TYPE) {
			uint8_t got_iid = resp[0] & RQDI_IID_MASK;
			if (got_iid != op->iid) {
				if (op->ctx->verbose)
					warnx("%s: wrong IID 0x%02x (expected 0x%02x)",
					      __func__, got_iid, op->iid);
				free(resp);
				pending_op_step_complete(op, -ENOMSG, NULL, 0,
							 NULL);
				return 0;
			}
		}
		pending_op_step_complete(op, 0, resp, resp_len, &resp_addr);
	}
	return 0;
}

static int cb_op_timeout(sd_event_source *s, uint64_t usec, void *data)
{
	struct pending_op *op = data;
	mctp_eid_t eid = op->req_addr.smctp_base.smctp_addr.s_addr;
	unsigned int max_attempts = op->step_no_retry ? 1 : STEP_MAX_ATTEMPTS;

	/* Mirror endpoint_query_addr(): every timed-out attempt of a
	 * non-discovery command raises TransportError; a discovery command
	 * is reported once, through DiscoveryCommandFailed, by its
	 * continuation. */
	if (!op->step_suppress && !op->step_discovery)
		report_transaction_error(op->ctx, ETIMEDOUT, MCTP_DIR_RX,
					 &op->req_addr, op->step_req,
					 op->step_req_len);

	if (op->step_attempt < max_attempts) {
		op_step_cb_t cb = op->step_cb;
		int rc;

		/* Tear down this attempt's socket and sources, then
		 * retransmit the same request (same IID). */
		if (op->io_src) {
			sd_event_source_disable_unref(op->io_src);
			op->io_src = NULL;
		}
		if (op->tm_src) {
			sd_event_source_disable_unref(op->tm_src);
			op->tm_src = NULL;
		}
		if (op->sock_fd >= 0) {
			close(op->sock_fd);
			op->sock_fd = -1;
		}
		free(op->send_buf);
		op->send_buf = NULL;

		op->step_attempt++;
		rc = step_send(op);
		if (rc < 0) {
			op->step_cb = cb;
			pending_op_step_complete(op, rc, NULL, 0, NULL);
		}
		return 0;
	}

	if (!op->step_suppress) {
		if (op->peer)
			op->peer->ping_failed_once = true;
	}

	op->step_fail_stage = MCTP_CTRL_CMD_FAIL_TIMEOUT;
	pending_op_step_complete(op, -ETIMEDOUT, NULL, 0, NULL);
	return 0;
}

/* EPOLLOUT handler: finish a send deferred by start_step (EAGAIN or
 * partial send), then arm the recv path. The step timer keeps running,
 * so a stuck send still times out. */
static int cb_op_send(sd_event_source *s, int fd, uint32_t revents, void *data)
{
	struct pending_op *op = data;
	size_t dest_len = op->send_ext_addr ?
				  sizeof(struct sockaddr_mctp_ext) :
				  sizeof(struct sockaddr_mctp);
	ssize_t rc;

	if (revents & EPOLLERR) {
		read_mctp_error_queue(op->ctx, fd, op->ctx->verbose,
				      &op->req_addr, op->step_req,
				      op->step_req_len, !op->step_discovery);
		op->step_fail_stage = MCTP_CTRL_CMD_FAIL_RECV;
		pending_op_step_complete(op, -EIO, NULL, 0, NULL);
		return 0;
	}

	rc = mctp_ops.mctp.sendto(fd, op->send_buf + op->send_off,
				  op->send_len - op->send_off, 0,
				  (struct sockaddr *)&op->send_addr, dest_len);
	if (rc < 0) {
		rc = -errno;
		if (rc == -EAGAIN || rc == -EWOULDBLOCK)
			return 0; /* still not writable — wait for next EPOLLOUT */
		op->step_fail_stage = MCTP_CTRL_CMD_FAIL_SEND;
		{
			mctp_eid_t eid =
				op->req_addr.smctp_base.smctp_addr.s_addr;
			if (!op->step_suppress) {
				warnx("%s: sendto cmd %s (0x%02x) to eid %d failed: %s",
				      __func__, command_str(op->cmd_code),
				      op->cmd_code, eid, strerror(-rc));
				if (!op->step_discovery)
					report_transaction_error(
						op->ctx, -rc, MCTP_DIR_TX,
						&op->req_addr, op->send_buf,
						op->send_len);
				if (op->peer)
					op->peer->ping_failed_once = true;
			}
		}
		pending_op_step_complete(op, rc, NULL, 0, NULL);
		return 0;
	}

	op->send_off += (size_t)rc;
	if (op->send_off < op->send_len)
		return 0; /* partial datagram accepted — keep waiting */

	/* Send complete. Drop the stashed request and switch this fd to the
	 * recv path. Tear down the EPOLLOUT source and add a fresh EPOLLIN
	 * source bound to cb_op_io (the shared receive callback). */
	free(op->send_buf);
	op->send_buf = NULL;

	if (op->io_src) {
		sd_event_source_disable_unref(op->io_src);
		op->io_src = NULL;
	}
	rc = sd_event_add_io(op->ctx->event, &op->io_src, fd,
			     EPOLLIN | EPOLLERR, cb_op_io, op);
	if (rc < 0) {
		warnx("%s: sd_event_add_io (EPOLLIN) failed: %s", __func__,
		      strerror(-(int)rc));
		pending_op_step_complete(op, (int)rc, NULL, 0, NULL);
		return 0;
	}
	return 0;
}

/* Validate a received control response exactly as the sync helpers do
 * through mctp_ctrl_validate_response(): minimum error-response length,
 * IID, opcode, completion code (-ENOTSUP for unsupported command,
 * -ECONNREFUSED otherwise), then the full success length. */
static int op_validate_response(struct pending_op *op, uint8_t *resp,
				size_t resp_len,
				const struct sockaddr_mctp_ext *resp_addr,
				size_t exp_size, const char *peer_str,
				uint8_t cmd_id)
{
	struct mctp_ctrl_cmd cmd = { 0 };

	cmd.req = op->step_req;
	cmd.req_len = op->step_req_len;
	cmd.suppress_logs = op->step_suppress;
	cmd.resp = resp;
	cmd.resp_len = resp_len;
	if (resp_addr)
		cmd.resp_addr = *resp_addr;

	return mctp_ctrl_validate_response(&cmd, exp_size, peer_str, op->iid,
					   cmd_id);
}

/* Report a failed discovery command through DiscoveryCommandFailed when
 * the step was launched with the discovery policy. Not gated on
 * ping_failed_once, since that flag is raised by any timed-out step.
 * Continuations call this once, after retries are exhausted. */
static void op_report_discovery_failure(
	struct pending_op *op, int ifindex, uint8_t cmd_code, mctp_eid_t eid,
	int rc, const uint8_t *resp, size_t resp_len,
	const struct sockaddr_mctp_ext *resp_addr, const char *reason)
{
	struct mctp_ctrl_cmd cmd = { 0 };

	if (rc >= 0 || !op->step_discovery)
		return;

	cmd.req = op->step_req;
	cmd.req_len = op->step_req_len;
	cmd.discovery = true;
	cmd.fail_stage = op->step_fail_stage;
	cmd.resp = (void *)resp;
	cmd.resp_len = resp_len;
	if (resp_addr)
		cmd.resp_addr = *resp_addr;

	report_discovery_command_failure(op->ctx, ifindex, cmd_code, eid, &cmd,
					 rc, reason);
}

/* ---------------- continuation: after the first wire step ------ */

void
op_after_get_endpoint_id_probe(struct pending_op *op, int rc, uint8_t *resp,
			       size_t resp_len,
			       const struct sockaddr_mctp_ext *resp_addr)
{
	struct ctx *ctx = op->ctx;
	struct mctp_ctrl_resp_get_eid *r = NULL;
	struct peer *peer = NULL;
	mctp_eid_t eid = 0;
	uint8_t ep_type = 0, medium_spec = 0;
	uint32_t net_id;
	const char *peer_path = NULL;

	/* Validate the Get Endpoint ID response as query_get_endpoint_id()
	 * does through mctp_ctrl_validate_response(). */
	if (rc == 0)
		rc = op_validate_response(op, resp, resp_len, resp_addr,
					  sizeof(*r), dest_phys_tostr(&op->dest),
					  MCTP_CTRL_CMD_GET_ENDPOINT_ID);
	if (rc < 0) {
		free(resp);
		pending_op_reply_error(op, rc);
		return;
	}
	r = (void *)resp;

	eid = r->eid;
	ep_type = r->eid_type;
	medium_spec = r->medium_data;
	free(resp);

	net_id = mctp_nl_net_byindex(ctx->nl, op->dest.ifindex);
	if (!net_id) {
		pending_op_reply_error(op, -EPROTO);
		return;
	}

	/* Existing entry handling mirrors get_endpoint_peer(). */
	peer = find_peer_by_phys(ctx, &op->dest);

	if (op->kind == OP_LEARN_ENDPOINT) {
		/* Learn: read-only — reject conflict and never SET. */
		if (peer && peer->eid != eid && eid != 0) {
			int crc = change_peer_eid(peer, eid);
			if (crc == -EEXIST) {
				sd_bus_error berr = SD_BUS_ERROR_NULL;
				sd_bus_error_setf(
					&berr, SD_BUS_ERROR_FILE_EXISTS,
					"Endpoint claimed EID %d which is already used",
					eid);
				sd_bus_reply_method_error(op->call, &berr);
				sd_bus_error_free(&berr);
				pending_op_release_call(op);
				if (peer)
					remove_peer(peer);
				pending_op_cleanup(op);
				return;
			}
			if (crc < 0) {
				remove_peer(peer);
				pending_op_reply_error(op, crc);
				return;
			}
		} else if (!peer) {
			if (eid == 0) {
				/* Not yet assigned — baseline returns
				 * (0, 0, "", 0). */
				sd_bus_reply_method_return(op->call, "yisb",
							   (uint8_t)0,
							   (int32_t)0, "", 0);
				pending_op_release_call(op);
				pending_op_cleanup(op);
				return;
			}
			rc = add_peer(ctx, &op->dest, eid, net_id, &peer,
				      /*allow_bridged=*/false);
			if (rc < 0) {
				pending_op_reply_error(op, rc);
				return;
			}
			add_peer_route(peer);
			/* Newly added — owned by op for cleanup if the rest
			 * of the chain fails. */
			op->peer = peer;
			op->is_dummy = true;
		}
		if (peer) {
			peer->endpoint_type = ep_type;
			peer->medium_spec = medium_spec;
			op->peer = peer;
			/* Query peer properties asynchronously; publish and
			 * reply in learn_after_qpp_done. */
			dispatch_setup_added_peer_async(op, peer,
							learn_after_qpp_done);
			return;
		}
		/* No peer (and not the eid==0 fast path handled above): nothing
		 * to query — reply with the empty path as the baseline did. */
		op->peer = NULL;
		op->is_dummy = false;
		pending_op_reply_success(op, "", 1);
		return;
	}

	/* OP_SETUP_ENDPOINT cases:
	 *  - no peer, no eid               → assign
	 *  - no peer, eid, not a bridge    → add_peer(eid)
	 *  - no peer, eid, bridge          → reassign (with bridge)
	 *  - peer, eid matching, bridge OK → fast return new=0
	 *  - peer, mismatch or no eid      → remove + reassign
	 */
	{
		bool is_bridge = GET_MCTP_GET_EID_EP_TYPE(ep_type) ==
				 MCTP_GET_EID_EP_TYPE_BRIDGE;

		if (peer) {
			if (eid && peer->eid == eid &&
			    is_bridge == !!peer->pool_size) {
				/* all matching: no action required */
				peer_path = path_from_peer(peer);
				if (!peer_path) {
					pending_op_reply_error(op, -EPROTO);
					return;
				}
				op->peer = peer;
				pending_op_reply_success(op, peer_path, 0);
				return;
			}
			/* state mismatch — remove and reassign */
			remove_peer(peer);
			peer = NULL;
		}

		/* simple allocation: try existing EID when not a bridge */
		if (eid && !is_bridge) {
			rc = add_peer(ctx, &op->dest, eid, net_id, &peer,
				      /*allow_bridged=*/false);
			if (rc == -EEXIST) {
				/* fall through to assign */
				peer = NULL;
			} else if (rc < 0) {
				pending_op_reply_error(op, rc);
				return;
			} else {
				add_peer_route(peer);
				peer->endpoint_type = ep_type;
				peer->medium_spec = medium_spec;
				/* This peer was just added for this op. Mark it
				 * disposable before dispatch so an early qpp_start
				 * failure removes the peer and its route in cleanup
				 * instead of leaking them. */
				pending_op_set_peer(op, peer);
				/* Query peer properties asynchronously; publish
				 * and reply in setup_simple_after_qpp_done. */
				dispatch_setup_added_peer_async(
					op, peer, setup_simple_after_qpp_done);
				return;
			}
		}
	}

	/* No fast tail: assign a fresh EID and send Set Endpoint ID, as
	 * AssignEndpoint does. The tail runs in op_after_set_endpoint_id. */
	{
		sd_bus_error berr = SD_BUS_ERROR_NULL;
		struct peer *new_peer = NULL;
		struct mctp_ctrl_cmd_set_eid req = { 0 };

		rc = endpoint_assign_prepare_peer(ctx, &berr, &op->dest, 0,
						  /*assign_bridge=*/true,
						  &new_peer);
		if (rc < 0) {
			if (op->call && sd_bus_error_is_set(&berr)) {
				sd_bus_reply_method_error(op->call, &berr);
				pending_op_release_call(op);
			}
			sd_bus_error_free(&berr);
			pending_op_reply_error(op, rc);
			return;
		}
		sd_bus_error_free(&berr);

		pending_op_set_peer(op, new_peer);

		mctp_ctrl_msg_hdr_init_req(&req.ctrl_hdr, mctp_next_iid(ctx),
					   MCTP_CTRL_CMD_SET_ENDPOINT_ID);
		req.operation = mctp_ctrl_cmd_set_eid_set_eid;
		req.eid = new_peer->eid;
		/* Set Endpoint ID of a newly enumerated endpoint is a discovery
		 * command (endpoint_assign_eid passes discovery = true). */
		pending_op_set_step_policy(op, true, false);
		rc = pending_op_launch_step_phys(op, STEP_SET_ENDPOINT_ID, &req,
						 sizeof(req),
						 op_after_set_endpoint_id);
		if (rc < 0)
			pending_op_reply_error(op, rc);
	}
}

/* Done continuation for SetupEndpoint's bridge-pool allocation. The
 * baseline ignored endpoint_allocate_eids()'s return value, so we
 * always proceed to the success reply regardless of rc. */
void setup_after_allocate_done(struct pending_op *op, int rc,
				      uint8_t *resp, size_t resp_len,
				      const struct sockaddr_mctp_ext *resp_addr)
{
	const char *peer_path;

	(void)rc;
	(void)resp;
	(void)resp_len;
	(void)resp_addr;

	peer_path = path_from_peer(op->peer);
	if (!peer_path) {
		pending_op_reply_error(op, -EPROTO);
		return;
	}
	if (op->ctx->verbose)
		fprintf(stderr,
			"setup_endpoint async: returning from endpoint_assign_eid %s\n",
			peer_tostr(op->peer));
	/* Peer is now committed — do not remove it in pending_op_cleanup. */
	op->is_dummy = false;
	pending_op_reply_success(op, peer_path, 1);
}

/* Done continuation for SetupEndpoint's assign-fresh path: publish,
 * service-state transition, then either the bridge-pool allocation or the
 * success reply. */
void setup_after_qpp_done(struct pending_op *op, int rc, uint8_t *resp,
				 size_t resp_len,
				 const struct sockaddr_mctp_ext *resp_addr)
{
	struct ctx *ctx = op->ctx;
	struct peer *peer = op->peer;
	const char *peer_path;

	(void)resp;
	(void)resp_len;
	(void)resp_addr;

	if (dispatch_qpp_failed(op, rc))
		return;

	rc = publish_peer(peer, true);
	if (dispatch_qpp_failed(op, rc))
		return;

	/* Service-state transition for non-bridge endpoints (was done inside
	 * endpoint_assign_eid's synchronous tail). */
	if (peer->pool_size == 0) {
		struct link *link =
			mctp_nl_get_link_userdata(ctx->nl, op->dest.ifindex);
		if (link && link->service_state == SERVICE_STATE_STARTING) {
			int lrc;

			link->service_state = SERVICE_STATE_ENABLED;
			lrc = sd_bus_emit_properties_changed(
				ctx->bus, link->path,
				OPENBMC_SERVICE_READINESS_IFACE, "State", NULL);
			if (lrc < 0)
				warnx("%s: Service state change emit failed: %d %s",
				      __func__, lrc, strerror(-lrc));
		}
	}

	peer->is_direct_endpoint = true;

	/* Bridge pool allocation is an async STEP_ALLOCATE_ENDPOINT_IDS chain;
	 * the reply moves into setup_after_allocate_done. */
	if (peer->pool_size) {
		allocate_eids_start(op, setup_after_allocate_done);
		return;
	}

	peer_path = path_from_peer(peer);
	if (!peer_path) {
		pending_op_reply_error(op, -EPROTO);
		return;
	}
	if (ctx->verbose)
		fprintf(stderr,
			"setup_endpoint async: returning from endpoint_assign_eid %s\n",
			peer_tostr(peer));
	/* Peer is now committed — do not remove it in pending_op_cleanup. */
	op->is_dummy = false;
	pending_op_reply_success(op, peer_path, 1);
}

/* ---------------- launchers ------------------------------------ */

/* Issue an async Get Endpoint ID probe against op->dest using
 * physical addressing. The continuation is op_after_get_endpoint_id_probe
 * for Setup/Learn. */
/* Issue an async step using physical addressing (Interface1-scope methods).
 * See endpoint_query_phys() for why smctp_addr must be zero.
 * The caller builds and owns the request struct. */
int pending_op_launch_step_phys(struct pending_op *op, enum op_step step,
				       const void *req, size_t req_len,
				       op_step_cb_t step_cb)
{
	struct sockaddr_mctp_ext addr = { 0 };

	addr.smctp_base.smctp_family = AF_MCTP;
	addr.smctp_base.smctp_network = 0;
	addr.smctp_base.smctp_addr.s_addr = 0;
	addr.smctp_base.smctp_type = MCTP_CTRL_HDR_MSG_TYPE;
	addr.smctp_base.smctp_tag = MCTP_TAG_OWNER;
	addr.smctp_ifindex = op->dest.ifindex;
	addr.smctp_halen = op->dest.hwaddr_len;
	memcpy(addr.smctp_haddr, op->dest.hwaddr, op->dest.hwaddr_len);

	return start_step(op, step, MCTP_CTRL_HDR_MSG_TYPE, req, req_len, &addr,
			  true, step_cb);
}

/* Issue an async step to an EID-routed peer (Network1-scope methods). */
int pending_op_launch_step_eid(struct pending_op *op, mctp_eid_t eid,
				      uint32_t net, enum op_step step,
				      const void *req, size_t req_len,
				      op_step_cb_t step_cb)
{
	struct sockaddr_mctp_ext addr = { 0 };

	addr.smctp_base.smctp_family = AF_MCTP;
	addr.smctp_base.smctp_network = net;
	addr.smctp_base.smctp_addr.s_addr = eid;
	addr.smctp_base.smctp_type = MCTP_CTRL_HDR_MSG_TYPE;
	addr.smctp_base.smctp_tag = MCTP_TAG_OWNER;

	return start_step(op, step, MCTP_CTRL_HDR_MSG_TYPE, req, req_len, &addr,
			  false, step_cb);
}

/* Continuation: Network1.LearnEndpoint — GET_ENDPOINT_ID response. */
void
op_after_net_learn_endpoint_get_eid(struct pending_op *op, int rc,
				    uint8_t *resp, size_t resp_len,
				    const struct sockaddr_mctp_ext *resp_addr)
{
	struct mctp_ctrl_resp_get_eid *r = NULL;
	const char *peer_path;

	if (rc == 0)
		rc = op_validate_response(op, resp, resp_len, resp_addr,
					  sizeof(*r),
					  op->peer ? peer_tostr_short(op->peer) :
						     dest_phys_tostr(&op->dest),
					  MCTP_CTRL_CMD_GET_ENDPOINT_ID);
	if (rc < 0) {
		warnx("Error getting endpoint id for %s. error %d %s",
		      op->peer ? peer_tostr(op->peer) : dest_phys_tostr(&op->dest),
		      rc, strerror(-rc));
		free(resp);
		pending_op_reply_error(op, rc);
		return;
	}
	r = (void *)resp;

	if (r->eid != op->static_eid) {
		warnx("Error getting endpoint eid %u not match expected eid %u.",
		      r->eid, op->static_eid);
		free(resp);
		pending_op_reply_error(op, -EPROTO);
		return;
	}
	free(resp);

	/* Query peer properties asynchronously; the publish and "sb" reply
	 * happen in the done continuation. */
	(void)peer_path;
	qpp_start(op, net_learn_after_qpp_done, true);
}

/* Done continuation for Network1.LearnEndpoint after the async
 * query_peer_properties chain: publish the peer and emit the "sb"
 * reply. Mirrors the former synchronous tail at this call site. */
void net_learn_after_qpp_done(struct pending_op *op, int rc,
				     uint8_t *resp, size_t resp_len,
				     const struct sockaddr_mctp_ext *resp_addr)
{
	const char *peer_path;
	int prc;

	(void)resp;
	(void)resp_len;
	(void)resp_addr;

	/* Extra#5 / develop policy: do not publish an endpoint whose message
	 * types / UUID could not be fetched (the async qpp chain reports the
	 * failure via rc). Bail with the error instead of publishing. */
	if (rc < 0) {
		pending_op_reply_error(op, rc);
		return;
	}

	prc = publish_peer(op->peer, false);
	if (prc < 0) {
		pending_op_reply_error(op, prc);
		return;
	}

	peer_path = path_from_peer(op->peer);
	if (!peer_path) {
		pending_op_reply_error(op, -EPROTO);
		return;
	}

	/* Peer is now a real, published entry — do not remove on cleanup. */
	op->is_dummy = false;

	if (!op->call) {
		pending_op_cleanup(op);
		return;
	}
	sd_bus_reply_method_return(op->call, "sb", peer_path, true);
	pending_op_release_call(op);
	pending_op_cleanup(op);
}

/* Done continuation for Interface1.GetRoutingTable after the chained
 * fragment loop: emit the empty reply. */
void
get_routing_table_done(struct pending_op *op, int rc, uint8_t *resp,
		       size_t resp_len,
		       const struct sockaddr_mctp_ext *resp_addr)
{
	(void)resp;
	(void)resp_len;
	(void)resp_addr;

	if (rc < 0) {
		pending_op_reply_error(op, rc);
		return;
	}

	if (!op->call) {
		pending_op_cleanup(op);
		return;
	}
	sd_bus_reply_method_return(op->call, "");
	pending_op_release_call(op);
	pending_op_cleanup(op);
}

/* Continuation: Interface1.GetRoutingTable — first fragment response. */
void
op_after_get_routing_table_first(struct pending_op *op, int rc, uint8_t *resp,
				 size_t resp_len,
				 const struct sockaddr_mctp_ext *resp_addr)
{
	free(resp);

	if (rc < 0) {
		pending_op_reply_error(op, rc);
		return;
	}

	routing_table_loop_start(op, op->peer, get_routing_table_done);
}

/* Continuation: AssignEndpoint / AssignEndpointStatic — SET_ENDPOINT_ID
 * response.  Mirrors endpoint_assign_eid post-SET processing and the
 * bridge-handling in assign_endpoint_finish_after_assign /
 * assign_endpoint_static_finish_after_assign. */
void op_after_set_endpoint_id(struct pending_op *op, int rc,
				     uint8_t *resp, size_t resp_len,
				     const struct sockaddr_mctp_ext *resp_addr)
{
	struct mctp_ctrl_resp_set_eid *r = NULL;
	sd_bus_error berr = SD_BUS_ERROR_NULL;
	struct peer *peer = op->peer;
	mctp_eid_t new_eid;
	uint8_t stat, req_pool_size = 0;
	const char *fail_reason = NULL;
	bool wire_done = false;

	/* Validate as endpoint_send_set_endpoint_id() does through
	 * mctp_ctrl_validate_response(): an error completion code is a
	 * 3-byte reply and must be inspected before the full-length check. */
	if (rc == 0)
		rc = op_validate_response(op, resp, resp_len, resp_addr,
					  sizeof(*r), dest_phys_tostr(&op->dest),
					  MCTP_CTRL_CMD_SET_ENDPOINT_ID);

	/* Map transport errors to D-Bus errors before the rc < 0 check. */
	if (rc == -ECONNREFUSED)
		sd_bus_error_setf(
			&berr, SD_BUS_ERROR_FAILED,
			"Endpoint returned failure to Set Endpoint ID");
	else if (rc == -ETIMEDOUT)
		sd_bus_error_setf(
			&berr, SD_BUS_ERROR_TIMEOUT,
			"Endpoint did not respond to Set Endpoint ID");
	else if (rc == -EIO)
		sd_bus_error_setf(&berr, SD_BUS_ERROR_FAILED,
				  "I/O error during Set Endpoint ID");

	if (rc < 0)
		goto set_err;
	r = (void *)resp;

	/* Parse response — mirrors endpoint_send_set_endpoint_id. */
	stat = r->status >> 4 & 0x3;
	new_eid = r->eid_set;

	if (stat == 0x01) {
		if (!mctp_eid_is_valid_unicast(new_eid)) {
			warnx("%s rejected assignment eid %d, and reported invalid eid %d",
			      dest_phys_tostr(&op->dest), peer->eid, new_eid);
			fail_reason = "endpoint rejected the EID assignment";
			/* Byte-for-byte with endpoint_assign_eid_pre_setup /
			 * endpoint_send_set_endpoint_id, which returned
			 * -ECONNREFUSED mapped to this D-Bus error. */
			sd_bus_error_setf(
				&berr, SD_BUS_ERROR_FAILED,
				"Endpoint returned failure to Set Endpoint ID");
			rc = -ECONNREFUSED;
			goto set_err;
		}
	} else if (stat == 0x00) {
		if (!mctp_eid_is_valid_unicast(new_eid)) {
			warnx("%s eid %d replied with invalid eid %d, but 'accepted'",
			      dest_phys_tostr(&op->dest), peer->eid, new_eid);
			fail_reason = "endpoint reported an invalid EID";
			sd_bus_error_setf(
				&berr, SD_BUS_ERROR_FAILED,
				"Endpoint returned failure to Set Endpoint ID");
			rc = -ECONNREFUSED;
			goto set_err;
		} else if (new_eid != peer->eid) {
			warnx("%s eid %d replied with different eid %d, but 'accepted'",
			      dest_phys_tostr(&op->dest), peer->eid, new_eid);
		}
	} else {
		warnx("%s unexpected status 0x%02x", dest_phys_tostr(&op->dest),
		      r->status);
	}

	if (r->status & 0x3) {
		req_pool_size = r->eid_pool_size;
		if (op->ctx->verbose)
			fprintf(stderr,
				"%s requested allocation of pool size = %d\n",
				dest_phys_tostr(&op->dest), req_pool_size);
	}
	free(resp);
	resp = NULL;
	wire_done = true;

	warnx("Successfully discovered and setup endpoint EID %d", new_eid);

	/* Pool size adjustments. Baseline endpoint_assign_eid_pre_setup limited
	 * (kept the allocated pool_size) whenever the EID was not caller-static,
	 * i.e. for SetupEndpoint and AssignEndpoint alike; only
	 * AssignEndpointStatic accepts the device-reported size verbatim. */
	if ((req_pool_size > peer->pool_size) &&
	    op->kind != OP_ASSIGN_ENDPOINT_STATIC) {
		warnx("EID %d: requested pool size (%d) > pool size available (%d), limiting.",
		      peer->eid, req_pool_size, peer->pool_size);
	} else {
		peer->pool_size = req_pool_size;
	}

	if (!peer->pool_size)
		peer->pool_start = 0;

	if (new_eid != peer->eid) {
		warnx("Mismatch of requested from received EID, resetting the pool");
		peer->pool_size = 0;
		peer->pool_start = 0;
		rc = change_peer_eid(peer, new_eid);
		if (rc == -EEXIST)
			sd_bus_error_setf(
				&berr, SD_BUS_ERROR_FAILED,
				"Endpoint requested EID %d instead of assigned %d, already used",
				new_eid, peer->eid);
		if (rc < 0)
			goto set_err;
	}

	/* ignore_message_types — AssignEndpointStatic only. */
	if (op->ignore_message_types_len > 0) {
		peer->ignore_message_types =
			malloc(op->ignore_message_types_len);
		if (!peer->ignore_message_types) {
			rc = -ENOMEM;
			goto set_err;
		}
		memcpy(peer->ignore_message_types, op->ignore_message_types,
		       op->ignore_message_types_len);
		peer->num_ignore_message_types = op->ignore_message_types_len;
	}

	/* Query peer properties asynchronously; publish, service-state and
	 * bridge post-processing and the success reply happen in the
	 * per-op_kind done callback. SetupEndpoint's fresh-assign path also
	 * lands here and uses its own tail (setup_after_qpp_done). */
	if (op->kind == OP_SETUP_ENDPOINT)
		dispatch_setup_added_peer_async(op, peer, setup_after_qpp_done);
	else
		dispatch_setup_added_peer_async(op, peer, assign_after_qpp_done);
	return;

set_err:
	/* The wire exchange failed (or its reply was rejected): report it as
	 * a discovery failure, as endpoint_send_set_endpoint_id() does. Local
	 * failures after the decode (change_peer_eid, OOM) are not reported. */
	if (!wire_done)
		op_report_discovery_failure(op, op->dest.ifindex,
					    MCTP_CTRL_CMD_SET_ENDPOINT_ID,
					    peer ? peer->eid : 0, rc, resp,
					    resp_len, resp_addr, fail_reason);
	free(resp);
	/* Zero pool fields if peer is still alive (is_dummy=true paths);
	 * pool route has not been installed yet at this point. */
	if (op->peer) {
		op->peer->pool_size = 0;
		op->peer->pool_start = 0;
	}
	if (op->call && sd_bus_error_is_set(&berr)) {
		sd_bus_reply_method_error(op->call, &berr);
		pending_op_release_call(op);
	}
	sd_bus_error_free(&berr);
	pending_op_reply_error(op, rc);
}

/* Done continuation for the Assign* dynamic-pool bridge tail. The
 * baseline ignored endpoint_allocate_eids()'s return value, so proceed
 * to the success reply regardless of rc. */
void assign_after_allocate_done(struct pending_op *op, int rc,
				       uint8_t *resp, size_t resp_len,
				       const struct sockaddr_mctp_ext *resp_addr)
{
	const char *peer_path;

	(void)rc;
	(void)resp;
	(void)resp_len;
	(void)resp_addr;

	peer_path = path_from_peer(op->peer);
	if (!peer_path) {
		pending_op_reply_error(op, -EPROTO);
		return;
	}
	op->is_dummy = false;
	pending_op_reply_success(op, peer_path, 1);
}

/* Done continuation for the Assign* bus-owner-bridge tail. Mirrors the
 * baseline query_routing_table error handling: on failure remove the
 * peer and reply error; otherwise commit and reply success. */
void assign_after_routing_done(struct pending_op *op, int rc,
				      uint8_t *resp, size_t resp_len,
				      const struct sockaddr_mctp_ext *resp_addr)
{
	const char *peer_path;

	(void)resp;
	(void)resp_len;
	(void)resp_addr;

	if (rc < 0) {
		if (op->peer) {
			remove_peer(op->peer);
			op->peer = NULL;
		}
		op->is_dummy = false;
		pending_op_reply_error(op, rc);
		return;
	}

	peer_path = path_from_peer(op->peer);
	if (!peer_path) {
		pending_op_reply_error(op, -EPROTO);
		return;
	}
	op->is_dummy = false;
	pending_op_reply_success(op, peer_path, 1);
}

/* Do the pre-query work (install the peer route for non-bridged
 * endpoints), then launch the async query_peer_properties chain.
 * Publishing is done by each flow's done_cb. */
void dispatch_setup_added_peer_async(struct pending_op *op,
					    struct peer *peer,
					    op_step_cb_t done_cb)
{
	struct net *n = lookup_net(peer->ctx, peer->net);

	if (!n) {
		bug_warn("%s Bad net %u", __func__, peer->net);
		remove_peer(peer);
		op->peer = NULL;
		op->is_dummy = false;
		pending_op_reply_error(op, -EPROTO);
		return;
	}

	/* The default MTU is set by add_peer() (develop: "Set default peer
	 * MTU earlier"), so nothing to do here before the route. */
	if (!is_eid_in_bridge_pool(n, peer->ctx, peer->eid, NULL)) {
		warnx("Adding route for non-bridged endpoint %s",
		      peer_tostr(peer));
		add_peer_route(peer);
	}

	op->peer = peer;
	/* setup_added_peer() runs query_peer_properties(peer, true):
	 * failures are reported through DiscoveryCommandFailed. */
	qpp_start(op, done_cb, true);
}

/* On a dispatch-path qpp failure, mirror setup_added_peer()'s failure
 * semantics: remove the peer and clear op->peer so cleanup does not double
 * remove, then reply the error. Returns true if it handled the failure. */
bool dispatch_qpp_failed(struct pending_op *op, int rc)
{
	if (rc >= 0)
		return false;
	if (op->peer) {
		remove_peer(op->peer);
		op->peer = NULL;
	}
	op->is_dummy = false;
	pending_op_reply_error(op, rc);
	return true;
}

/* Done continuation for AssignEndpoint / AssignEndpointStatic after the
 * async qpp chain. Mirrors the post-setup_added_peer() tail of
 * op_after_set_endpoint_id: publish, service-state transition, bridge
 * post-processing (async allocate / routing-table loop) and the reply. */
void assign_after_qpp_done(struct pending_op *op, int rc, uint8_t *resp,
				  size_t resp_len,
				  const struct sockaddr_mctp_ext *resp_addr)
{
	struct ctx *ctx = op->ctx;
	struct peer *peer = op->peer;
	const char *peer_path;

	(void)resp;
	(void)resp_len;
	(void)resp_addr;

	if (dispatch_qpp_failed(op, rc))
		return;

	/* setup_added_peer() published with add_route=true after the query. */
	rc = publish_peer(peer, true);
	if (dispatch_qpp_failed(op, rc))
		return;

	/* Service-state transition for non-bridge endpoints. */
	if (peer->pool_size == 0) {
		struct link *link =
			mctp_nl_get_link_userdata(ctx->nl, op->dest.ifindex);
		if (link && link->service_state == SERVICE_STATE_STARTING) {
			int lrc;

			link->service_state = SERVICE_STATE_ENABLED;
			lrc = sd_bus_emit_properties_changed(
				ctx->bus, link->path,
				OPENBMC_SERVICE_READINESS_IFACE, "State", NULL);
			if (lrc < 0)
				warnx("%s: Service state change emit failed: %d %s",
				      __func__, lrc, strerror(-lrc));
		}
	}

	peer->is_direct_endpoint = true;
	peer_path = path_from_peer(peer);
	if (!peer_path) {
		remove_peer(peer);
		op->peer = NULL;
		op->is_dummy = false;
		pending_op_reply_error(op, -EPROTO);
		return;
	}

	/* ignore_eids — AssignEndpointStatic only. */
	if (op->kind == OP_ASSIGN_ENDPOINT_STATIC && op->ignore_eids_len > 0) {
		peer->ignore_eids = malloc(op->ignore_eids_len);
		if (!peer->ignore_eids) {
			remove_peer(peer);
			op->peer = NULL;
			op->is_dummy = false;
			pending_op_reply_error(op, -ENOMEM);
			return;
		}
		memcpy(peer->ignore_eids, op->ignore_eids, op->ignore_eids_len);
		peer->num_ignore_eids = op->ignore_eids_len;
	}

	/* Bridge post-processing — async allocate / routing-table loop. */
	if (peer->pool_size > 0) {
		if (op->kind == OP_ASSIGN_ENDPOINT)
			peer->pool_start = peer->eid + 1;
		else
			peer->pool_start = op->static_pool_start;
		/* baseline ignored endpoint_allocate_eids() rc */
		allocate_eids_start(op, assign_after_allocate_done);
		return;
	} else if (GET_ENDPOINT_TYPE(peer->endpoint_type) ==
		   MCTP_BUS_OWNER_BRIDGE) {
		rc = peer_alloc_static_pool_eids(peer);
		if (rc < 0) {
			remove_peer(peer);
			op->peer = NULL;
			op->is_dummy = false;
			pending_op_reply_error(op, rc);
			return;
		}
		sd_bus_add_object_vtable(peer->ctx->bus, &peer->slot_bridge,
					 peer->path, CC_MCTP_DBUS_IFACE_BRIDGE,
					 bus_endpoint_bridge, peer);
		rc = sd_bus_emit_interfaces_added(peer->ctx->bus, peer->path,
						  CC_MCTP_DBUS_IFACE_BRIDGE,
						  NULL);
		if (rc < 0)
			warnx("Failed to emit add %s signal for endpoint %d : %s",
			      CC_MCTP_DBUS_IFACE_BRIDGE, peer->eid,
			      strerror(-rc));
		routing_table_loop_start(op, peer, assign_after_routing_done);
		return;
	}

	/* Peer is now committed — do not remove on cleanup. */
	op->is_dummy = false;
	pending_op_reply_success(op, peer_path, 1);
}

/* Done continuation for LearnEndpoint after the async qpp chain. Mirrors
 * the post-setup_added_peer() tail in op_after_get_endpoint_id_probe's
 * OP_LEARN_ENDPOINT branch. */
void learn_after_qpp_done(struct pending_op *op, int rc, uint8_t *resp,
				 size_t resp_len,
				 const struct sockaddr_mctp_ext *resp_addr)
{
	struct peer *peer = op->peer;
	const char *peer_path;

	(void)resp;
	(void)resp_len;
	(void)resp_addr;

	if (dispatch_qpp_failed(op, rc))
		return;

	rc = publish_peer(peer, true);
	if (dispatch_qpp_failed(op, rc))
		return;

	op->is_dummy = false;
	peer->is_direct_endpoint = true;

	/* A bridge endpoint discovered via LearnEndpoint can't be allocated a
	 * pool here (read-only, needs an AllocateEndpointIDs round-trip). */
	if (GET_MCTP_GET_EID_EP_TYPE(peer->endpoint_type) ==
	    MCTP_GET_EID_EP_TYPE_BRIDGE) {
		warnx("LearnEndpoint, eid %d: Get EID response "
		      "indicated a bridge with existing EID, "
		      "but no pool is assignable",
		      peer->eid);
	}

	peer_path = path_from_peer(peer);
	if (!peer_path) {
		pending_op_reply_error(op, -EPROTO);
		return;
	}
	pending_op_reply_success(op, peer_path, 1);
}

/* Done continuation for SetupEndpoint's simple-allocation (existing EID,
 * non-bridge) path in op_after_get_endpoint_id_probe. */
void
setup_simple_after_qpp_done(struct pending_op *op, int rc, uint8_t *resp,
			    size_t resp_len,
			    const struct sockaddr_mctp_ext *resp_addr)
{
	const char *peer_path;

	(void)resp;
	(void)resp_len;
	(void)resp_addr;

	if (dispatch_qpp_failed(op, rc))
		return;

	rc = publish_peer(op->peer, true);
	if (dispatch_qpp_failed(op, rc))
		return;

	peer_path = path_from_peer(op->peer);
	if (!peer_path) {
		pending_op_reply_error(op, -EPROTO);
		return;
	}
	op->is_dummy = false;
	pending_op_reply_success(op, peer_path, 1);
}

/* ---------------- async query_peer_properties chain -----------------
 *
 * Chained steps: msgtypes → uuid → endpoint-id confirm → optional
 * routing-data. Non-timeout errors on a sub-step are warned about and
 * ignored, so the chain always ends in qpp_done_cb. */

/* Outer re-launches (new IID) of a timed-out Get Message Type Support /
 * Get Endpoint UUID, on top of the step engine's same-IID retransmission
 * (STEP_MAX_ATTEMPTS): 2 launches x 2 transmissions = 4 attempts. */
#define QPP_MAX_RETRIES 1

/* Build + launch one EID-routed control request for the qpp chain. */
int qpp_launch_msgtypes(struct pending_op *op)
{
	struct mctp_ctrl_cmd_get_msg_type_support req;

	mctp_ctrl_msg_hdr_init_req(&req.ctrl_hdr, mctp_next_iid(op->ctx),
				   MCTP_CTRL_CMD_GET_MESSAGE_TYPE_SUPPORT);
	pending_op_set_step_policy(op, op->qpp_discovery, false);
	return pending_op_launch_step_eid(op, op->peer->eid, op->peer->net,
					  STEP_QPP_MSGTYPES, &req, sizeof(req),
					  op_after_qpp_msgtypes);
}

/* Get Vendor Defined Message Support, one set selector per step. The
 * command is optional and not a discovery command: failures are logged
 * (verbose) and ignored, as in query_get_peer_vdm_types(). */
int qpp_launch_vdm(struct pending_op *op)
{
	struct mctp_ctrl_cmd_get_vdm_support req = { 0 };

	mctp_ctrl_msg_hdr_init_req(&req.ctrl_hdr, mctp_next_iid(op->ctx),
				   MCTP_CTRL_CMD_GET_VENDOR_MESSAGE_SUPPORT);
	req.vendor_id_set_selector = op->qpp_vdm_selector;
	pending_op_set_step_policy(op, false, false);
	return pending_op_launch_step_eid(op, op->peer->eid, op->peer->net,
					  STEP_QPP_VDM, &req, sizeof(req),
					  op_after_qpp_vdm);
}

int qpp_launch_uuid(struct pending_op *op)
{
	struct mctp_ctrl_cmd_get_uuid req;

	mctp_ctrl_msg_hdr_init_req(&req.ctrl_hdr, mctp_next_iid(op->ctx),
				   MCTP_CTRL_CMD_GET_ENDPOINT_UUID);
	pending_op_set_step_policy(op, op->qpp_discovery, false);
	return pending_op_launch_step_eid(op, op->peer->eid, op->peer->net,
					  STEP_QPP_UUID, &req, sizeof(req),
					  op_after_qpp_uuid);
}

int qpp_launch_endpoint_id(struct pending_op *op)
{
	struct mctp_ctrl_cmd_get_eid req = { 0 };

	mctp_ctrl_msg_hdr_init_req(&req.ctrl_hdr, mctp_next_iid(op->ctx),
				   MCTP_CTRL_CMD_GET_ENDPOINT_ID);
	/* The sync query_peer_properties calls query_get_endpoint_id with a
	 * non-NULL peer, which routes via endpoint_query_peer() (EID
	 * addressing) and retry = false. Preserve both here. */
	pending_op_set_step_policy(op, false, true);
	return pending_op_launch_step_eid(op, op->peer->eid, op->peer->net,
					  STEP_QPP_ENDPOINT_ID, &req,
					  sizeof(req), op_after_qpp_endpoint_id);
}

int qpp_launch_routing_data(struct pending_op *op)
{
	struct mctp_ctrl_cmd_get_routing_table req;

	memset(&req, 0, sizeof(req));
	req.ctrl_hdr.rq_dgram_inst = RQDI_REQ | mctp_next_iid(op->ctx);
	req.ctrl_hdr.command_code = MCTP_CTRL_CMD_GET_ROUTING_TABLE_ENTRIES;
	req.entry_handle = op->rt_next_handle;
	/* Routing data is fetched from the pool-owner peer (EID-routed),
	 * matching query_get_peer_routing_data(pool_owner_peer, ...). */
	pending_op_set_step_policy(op, false, false);
	return pending_op_launch_step_eid(op, op->rt_pool_peer->eid,
					  op->rt_pool_peer->net,
					  STEP_QPP_ROUTING_DATA, &req,
					  sizeof(req), op_after_qpp_routing_data);
}

/* Kick off the query_peer_properties chain. discovery mirrors
 * query_peer_properties(peer, discovery): command failures are reported
 * through DiscoveryCommandFailed only while discovering a new endpoint. */
void qpp_start(struct pending_op *op, op_step_cb_t qpp_done_cb, bool discovery)
{
	int rc;

	op->qpp_done_cb = qpp_done_cb;
	op->qpp_discovery = discovery;
	op->step_retries = 0;
	op->qpp_vdm_selector = 0;
	free(op->qpp_vdm_types);
	op->qpp_vdm_types = NULL;
	op->qpp_num_vdm_types = 0;
	memset(op->qpp_uuid, 0, sizeof(op->qpp_uuid));

	rc = qpp_launch_msgtypes(op);
	if (rc < 0)
		op->qpp_done_cb(op, rc, NULL, 0, NULL);
}

void op_after_qpp_msgtypes(struct pending_op *op, int rc, uint8_t *resp,
				  size_t resp_len,
				  const struct sockaddr_mctp_ext *resp_addr)
{
	struct peer *peer = op->peer;
	struct mctp_ctrl_resp_get_msg_type_support *r = NULL;
	size_t expect_size;
	int lrc;

	/* Retry on timeout (max QPP_MAX_RETRIES), matching the sync loop. */
	if (rc == -ETIMEDOUT && op->step_retries < QPP_MAX_RETRIES) {
		if (op->ctx->verbose)
			warnx("Retrying to get endpoint types for %s. Attempt %u",
			      peer_tostr(peer), op->step_retries + 1);
		op->step_retries++;
		lrc = qpp_launch_msgtypes(op);
		if (lrc < 0)
			op->qpp_done_cb(op, lrc, NULL, 0, NULL);
		return;
	}
	op->step_retries = 0;

	/* Don't publish an endpoint without its message types: on
	 * retry-exhausted timeout or any other error, bail out. */
	/* Decode mirrors query_get_peer_msgtypes() through the shared
	 * mctp_ctrl_validate_response(). A malformed / failed response is
	 * fatal — bail like the sync helper. */
	if (rc == 0)
		rc = op_validate_response(
			op, resp, resp_len, resp_addr, sizeof(*r),
			peer_tostr_short(peer),
			MCTP_CTRL_CMD_GET_MESSAGE_TYPE_SUPPORT);
	if (rc == 0) {
		r = (void *)resp;
		expect_size = sizeof(*r) + r->msg_type_count;
		if (resp_len != expect_size) {
			warnx("%s: bad reply length. got %zu, expected %zu, %d entries. dest %s",
			      __func__, resp_len, expect_size,
			      r->msg_type_count, peer_tostr(peer));
			rc = -ENOMSG;
		}
	}
	if (rc < 0) {
		if (peer->ctx->verbose)
			warnx("Error getting endpoint types for %s. Error %d %s",
			      peer_tostr(peer), -rc, strerror(-rc));
		/* Final failure (retries exhausted or a bad reply): reported
		 * once, as query_get_peer_msgtypes(last_attempt) does. */
		op_report_discovery_failure(
			op, peer->phys.ifindex,
			MCTP_CTRL_CMD_GET_MESSAGE_TYPE_SUPPORT, peer->eid, rc,
			resp, resp_len, resp_addr, NULL);
		free(resp);
		op->qpp_done_cb(op, rc, NULL, 0, NULL);
		return;
	}
	{
		uint8_t *new_message_types = malloc(r->msg_type_count);
		if (!new_message_types) {
			free(resp);
			op->qpp_done_cb(op, -ENOMEM, NULL, 0, NULL);
			return;
		}
		free(peer->message_types);
		peer->message_types = new_message_types;
		peer->num_message_types = 0;

		size_t idx = 0;
		uint8_t count_ignore = 0;
		for (size_t resp_i = 0; resp_i < r->msg_type_count; resp_i++) {
			bool ignore = false;
			for (size_t k = 0; k < peer->num_ignore_message_types;
			     k++) {
				if (peer->ignore_message_types[k] ==
				    ((uint8_t *)(r + 1))[resp_i]) {
					ignore = true;
					count_ignore++;
					break;
				}
			}
			if (!ignore)
				peer->message_types[idx++] =
					((uint8_t *)(r + 1))[resp_i];
		}
		peer->num_message_types = r->msg_type_count - count_ignore;
	}
	free(resp);

	/* Query vendor-defined message types if the endpoint advertises VDM
	 * (query_peer_properties: supports_vdm). */
	for (size_t i = 0; i < peer->num_message_types; i++) {
		if (peer->message_types[i] == MCTP_TYPE_VENDOR_IANA ||
		    peer->message_types[i] == MCTP_TYPE_VENDOR_PCIE) {
			op->qpp_vdm_selector = 0;
			lrc = qpp_launch_vdm(op);
			if (lrc < 0)
				op->qpp_done_cb(op, lrc, NULL, 0, NULL);
			return;
		}
	}

	lrc = qpp_launch_uuid(op);
	if (lrc < 0)
		op->qpp_done_cb(op, lrc, NULL, 0, NULL);
}

/* End of the VDM selector loop: commit the collected sets on success,
 * otherwise log (verbose) and drop them; either way continue with Get
 * Endpoint UUID, as query_peer_properties() ignores the VDM query result. */
static void qpp_vdm_finish(struct pending_op *op, int rc)
{
	struct peer *peer = op->peer;
	int lrc;

	if (rc == 0) {
		free(peer->vdm_types);
		peer->vdm_types = op->qpp_vdm_types;
		peer->num_vdm_types = op->qpp_num_vdm_types;
	} else {
		if (peer->ctx->verbose) {
			errno = -rc;
			warn("Error getting vendor message types for %s",
			     peer_tostr(peer));
		}
		free(op->qpp_vdm_types);
	}
	op->qpp_vdm_types = NULL;
	op->qpp_num_vdm_types = 0;

	lrc = qpp_launch_uuid(op);
	if (lrc < 0)
		op->qpp_done_cb(op, lrc, NULL, 0, NULL);
}

/* One Get Vendor Defined Message Support response. Mirrors the loop body
 * of query_get_peer_vdm_types(): validate, size-check by format, append
 * the set, then either finish (no more sets) or fetch the next selector. */
void op_after_qpp_vdm(struct pending_op *op, int rc, uint8_t *resp,
		      size_t resp_len, const struct sockaddr_mctp_ext *resp_addr)
{
	struct peer *peer = op->peer;
	struct mctp_ctrl_resp_get_vdm_support *r;
	struct vdm_type_support *new_vdm, *cur;
	size_t expect_size;
	uint8_t fmt;
	int lrc;

	if (rc == 0)
		rc = op_validate_response(
			op, resp, resp_len, resp_addr, sizeof(*r),
			peer_tostr_short(peer),
			MCTP_CTRL_CMD_GET_VENDOR_MESSAGE_SUPPORT);
	if (rc < 0) {
		free(resp);
		qpp_vdm_finish(op, rc);
		return;
	}
	r = (void *)resp;

	fmt = r->vendor_id_format;
	if (fmt == MCTP_GET_VDM_SUPPORT_PCIE_FORMAT_ID) {
		expect_size = sizeof(*r) + sizeof(struct mctp_vdm_pcie_data);
	} else if (fmt == MCTP_GET_VDM_SUPPORT_IANA_FORMAT_ID) {
		expect_size = sizeof(*r) + sizeof(struct mctp_vdm_iana_data);
	} else {
		warnx("%s: bad vendor_id_format 0x%02x dest %s", __func__, fmt,
		      peer_tostr(peer));
		free(resp);
		qpp_vdm_finish(op, -ENOMSG);
		return;
	}
	if (resp_len != expect_size) {
		warnx("%s: bad reply length. got %zu, expected %zu dest %s",
		      __func__, resp_len, expect_size, peer_tostr(peer));
		free(resp);
		qpp_vdm_finish(op, -ENOMSG);
		return;
	}

	new_vdm = realloc(op->qpp_vdm_types,
			  (op->qpp_num_vdm_types + 1) * sizeof(*new_vdm));
	if (!new_vdm) {
		free(resp);
		qpp_vdm_finish(op, -ENOMEM);
		return;
	}
	op->qpp_vdm_types = new_vdm;
	cur = &op->qpp_vdm_types[op->qpp_num_vdm_types];
	memset(cur, 0, sizeof(*cur));
	cur->format = fmt;
	if (fmt == MCTP_GET_VDM_SUPPORT_IANA_FORMAT_ID) {
		struct mctp_vdm_iana_data *d = (void *)(r + 1);

		cur->vendor_id.iana = be32toh(d->enterprise_number);
		cur->cmd_set = be16toh(d->cmd_set);
	} else {
		struct mctp_vdm_pcie_data *d = (void *)(r + 1);

		cur->vendor_id.pcie = be16toh(d->vendor_id);
		cur->cmd_set = be16toh(d->cmd_set);
	}
	op->qpp_num_vdm_types++;

	if (r->vendor_id_set_selector == MCTP_GET_VDM_SUPPORT_NO_MORE_CAP_SET) {
		free(resp);
		qpp_vdm_finish(op, 0);
		return;
	}
	if (r->vendor_id_set_selector != (uint8_t)(op->qpp_vdm_selector + 1)) {
		/* DSP0236 requires set selectors to be monotonically
		 * increasing by 1 */
		warnx("peer %s reporting invalid VDM selector 0x%02x, "
		      "expected 0x%02x",
		      peer_tostr_short(peer), r->vendor_id_set_selector,
		      op->qpp_vdm_selector + 1);
		free(resp);
		qpp_vdm_finish(op, -EPROTO);
		return;
	}
	free(resp);

	op->qpp_vdm_selector++;
	lrc = qpp_launch_vdm(op);
	if (lrc < 0)
		op->qpp_done_cb(op, lrc, NULL, 0, NULL);
}

void op_after_qpp_uuid(struct pending_op *op, int rc, uint8_t *resp,
			      size_t resp_len,
			      const struct sockaddr_mctp_ext *resp_addr)
{
	struct peer *peer = op->peer;
	struct mctp_ctrl_resp_get_uuid *r = NULL;
	int lrc;

	if (rc == -ETIMEDOUT && op->step_retries < QPP_MAX_RETRIES) {
		if (op->ctx->verbose)
			warnx("Retrying to get peer UUID for %s. Attempt %u",
			      peer_tostr(peer), op->step_retries + 1);
		op->step_retries++;
		lrc = qpp_launch_uuid(op);
		if (lrc < 0)
			op->qpp_done_cb(op, lrc, NULL, 0, NULL);
		return;
	}
	op->step_retries = 0;

	/* mctp_ctrl_validate_response(): an unsupported-command reply maps
	 * to -ENOTSUP for the fake-UUID fallback below. */
	if (rc == 0)
		rc = op_validate_response(op, resp, resp_len, resp_addr,
					  sizeof(*r), peer_tostr_short(peer),
					  MCTP_CTRL_CMD_GET_ENDPOINT_UUID);
	if (rc == 0) {
		r = (void *)resp;
		memcpy(op->qpp_uuid, r->uuid, 16);
	}

	/* Get Endpoint UUID is optional: an unsupported-command response is
	 * not a discovery failure. Retried timeouts were handled above, so
	 * this is the final attempt (query_get_peer_uuid last_attempt). */
	if (rc < 0 && rc != -ENOTSUP)
		op_report_discovery_failure(op, peer->phys.ifindex,
					    MCTP_CTRL_CMD_GET_ENDPOINT_UUID,
					    peer->eid, rc, resp, resp_len,
					    resp_addr, NULL);
	free(resp);

	/* Mirror sync query_get_peer_uuid handling (develop / extra#5):
	 * success -> set; -ENOTSUP -> fake UUID (uuid[15] = eid) then set;
	 * any other error (incl. retry-exhausted timeout) is fatal — bail
	 * out of the chain rather than publishing without a UUID. */
	if (rc == 0) {
		peer_set_uuid(peer, op->qpp_uuid);
	} else if (rc == -ENOTSUP) {
		/* Fake UUID so clients can still use the property even when
		 * the device does not support Get Endpoint UUID (e.g. some
		 * NVMe drives). Byte-for-byte: only uuid[15] = eid is set. */
		memset(op->qpp_uuid, 0, sizeof(op->qpp_uuid));
		op->qpp_uuid[15] = peer->eid;
		peer_set_uuid(peer, op->qpp_uuid);
	} else {
		if (peer->ctx->verbose)
			warnx("Error getting UUID for %s. Error %d %s",
			      peer_tostr(peer), rc, strerror(-rc));
		op->qpp_done_cb(op, rc, NULL, 0, NULL);
		return;
	}

	lrc = qpp_launch_endpoint_id(op);
	if (lrc < 0)
		op->qpp_done_cb(op, lrc, NULL, 0, NULL);
}

void
op_after_qpp_endpoint_id(struct pending_op *op, int rc, uint8_t *resp,
			 size_t resp_len,
			 const struct sockaddr_mctp_ext *resp_addr)
{
	struct peer *peer = op->peer;
	struct mctp_ctrl_resp_get_eid *r = NULL;
	struct peer *pool_owner_peer = NULL;
	struct net *n;
	mctp_eid_t eid = 0;
	uint8_t ep_type = 0, medium_spec = 0;
	int lrc;

	/* Sync query_peer_properties does NOT retry the endpoint-id confirm
	 * (only msgtypes/uuid retry). On any error it warns and ignores
	 * (rc = 0). Preserve that exactly. */
	if (rc == 0)
		rc = op_validate_response(op, resp, resp_len, resp_addr,
					  sizeof(*r), peer_tostr_short(peer),
					  MCTP_CTRL_CMD_GET_ENDPOINT_ID);
	if (rc == 0) {
		r = (void *)resp;
		eid = r->eid;
		ep_type = r->eid_type;
		medium_spec = r->medium_data;
	}
	free(resp);

	if (rc < 0) {
		if (peer->ctx->verbose)
			warnx("Error getting endpoint ID for %s. Ignoring error %d %s",
			      peer_tostr(peer), rc, strerror(-rc));
	} else {
		if (peer->eid == eid) {
			peer->endpoint_type = ep_type;
			peer->medium_spec = medium_spec;
		} else {
			warnx("GET_ENDPOINT_ID: Endpoint ID mismatch for %s: %d != %d",
			      peer_tostr(peer), peer->eid, eid);
		}
	}

	/* Bridge-pool check — identical to the sync tail. If the peer sits
	 * in a bridge pool, copy pool-owner fields and fetch routing data;
	 * otherwise the chain is complete. */
	n = lookup_net(peer->ctx, peer->net);
	if (!peer->routing_table_entry &&
	    is_eid_in_bridge_pool(n, peer->ctx, peer->eid, &pool_owner_peer)) {
		if (peer->pool_owner_eid != pool_owner_peer->eid) {
			peer->phys.hwaddr_len = pool_owner_peer->phys.hwaddr_len;
			peer->phys.ifindex = pool_owner_peer->phys.ifindex;
			peer->pool_owner_eid = pool_owner_peer->eid;
			peer->local_eid = pool_owner_peer->local_eid;
			peer->is_direct_endpoint = false;
			memcpy(peer->phys.hwaddr, pool_owner_peer->phys.hwaddr,
			       pool_owner_peer->phys.hwaddr_len);
			/* Allocate + size the ignore-message-types buffer before
			 * copying into it (mirrors the sync pool-owner copy path);
			 * copying into an unsized/NULL buffer corrupts memory. */
			peer->num_ignore_message_types =
				pool_owner_peer->num_ignore_message_types;
			peer->ignore_message_types =
				malloc(pool_owner_peer->num_ignore_message_types);
			if (peer->num_ignore_message_types &&
			    !peer->ignore_message_types) {
				warnx("Failed to allocate memory for ignore message types");
				pending_op_reply_error(op, -ENOMEM);
				return;
			}
			memset(peer->ignore_message_types, 0,
			       pool_owner_peer->num_ignore_message_types);
			memcpy(peer->ignore_message_types,
			       pool_owner_peer->ignore_message_types,
			       pool_owner_peer->num_ignore_message_types);
		}

		op->rt_pool_peer = pool_owner_peer;
		op->rt_next_handle = 0;
		lrc = qpp_launch_routing_data(op);
		if (lrc < 0)
			op->qpp_done_cb(op, lrc, NULL, 0, NULL);
		return;
	}

	op->qpp_done_cb(op, 0, NULL, 0, NULL);
}

void
op_after_qpp_routing_data(struct pending_op *op, int rc, uint8_t *resp,
			  size_t resp_len,
			  const struct sockaddr_mctp_ext *resp_addr)
{
	struct peer *peer = op->peer;
	struct mctp_ctrl_resp_get_routing_table *r = NULL;

	/* Scan fragments for the entry whose starting_eid == peer->eid, copy
	 * it into peer->routing_table_entry, and stop. Errors are ignored.
	 * Further fragments are chained through this same step. */
	if (rc == 0)
		rc = mctp_ctrl_validate_get_routing_table_response(
			resp, resp_len, peer_tostr_short(op->rt_pool_peer),
			op->iid, (struct sockaddr_mctp_ext *)resp_addr,
			op->step_suppress);
	if (rc < 0) {
		if (peer->ctx->verbose)
			warnx("Error getting routing data for %s. Ignoring error %d %s",
			      peer_tostr(peer), rc, strerror(-rc));
		free(resp);
		goto done;
	}
	r = (void *)resp;

	if (peer->ctx->verbose)
		fprintf(stderr,
			"%s: returned routing entries %x, next handle %x\n",
			__func__, r->number_of_entries, r->next_entry_handle);

	if (r->number_of_entries) {
		struct get_routing_table_entry *entry =
			(struct get_routing_table_entry *)r->routing_entries;
		for (uint8_t idx = 0; idx < r->number_of_entries; idx++) {
			if (entry->starting_eid == peer->eid) {
				size_t entry_size =
					sizeof(struct get_routing_table_entry) +
					entry->phys_address_size;
				peer->routing_table_entry =
					malloc(entry_size);
				if (peer->routing_table_entry) {
					memset(peer->routing_table_entry, 0,
					       entry_size);
					memcpy(peer->routing_table_entry, entry,
					       entry_size);
				}
				free(resp);
				goto done;
			}
			entry = (struct get_routing_table_entry *)
				routing_table_entry_next(entry);
		}
	}

	/* More fragments? Chain the next one (next handle 0xFF means done). */
	if (r->next_entry_handle != 0 && r->next_entry_handle != 0xFF) {
		int lrc;
		op->rt_next_handle = r->next_entry_handle;
		free(resp);
		lrc = qpp_launch_routing_data(op);
		if (lrc < 0)
			op->qpp_done_cb(op, lrc, NULL, 0, NULL);
		return;
	}
	free(resp);

done:
	if (!peer->routing_table_entry)
		warnx("No routing data found for %s", peer_tostr(peer));
	op->qpp_done_cb(op, 0, NULL, 0, NULL);
}

/* ---------------- async endpoint_allocate_eids ---------------------- */
void allocate_eids_start(struct pending_op *op, op_step_cb_t on_done)
{
	struct peer *peer = op->peer;
	struct mctp_ctrl_cmd_allocate_eids req = { 0 };
	int rc;

	op->rt_done_cb = on_done;

	if (!mctp_eid_is_valid_unicast(peer->pool_start)) {
		warnx("Invalid pool start %d", peer->pool_start);
		on_done(op, -1, NULL, 0, NULL);
		return;
	}
	/* Validate pool range is fully within [eid_alloc_min,
	 * eid_alloc_max] before allocating to avoid landing on 0xFF. */
	if (peer->pool_size - 1 > (uint8_t)(eid_alloc_max - peer->pool_start) ||
	    !eid_pool_range_is_valid(peer->pool_start, peer->pool_size)) {
		warnx("WARNING: bridge pool [%u..%u] out of allocatable range [%u..%u]; rejecting",
		      peer->pool_start, peer->pool_start + peer->pool_size - 1,
		      eid_alloc_min, eid_alloc_max);
		on_done(op, -1, NULL, 0, NULL);
		return;
	}
	peer->pool_start =
		get_pool_start(peer, peer->pool_start, peer->pool_size);
	if (peer->pool_start == eid_alloc_max) {
		warnx("%s failed to find contiguous EIDs of required size",
		      __func__);
		/* sync returns 0 (success, no allocation) in this case */
		on_done(op, 0, NULL, 0, NULL);
		return;
	}
	if (peer->ctx->verbose)
		fprintf(stderr,
			"%s Asking for contiguous EIDs for pool with start eid %d and size %d\n",
			__func__, peer->pool_start, peer->pool_size);

	rc = add_pool_gw_routes_ignore_aware(peer);
	if (rc < 0 && rc != -EEXIST) {
		warnx("Failed to add gateway route for EID %d: %s", peer->eid,
		      strerror(-rc));
		int drc = del_pool_gw_routes_ignore_aware(peer);
		if (drc < 0)
			warnx("Rollback of partial pool gw routes failed: %s",
			      strerror(-drc));
		on_done(op, rc, NULL, 0, NULL);
		return;
	}

	mctp_ctrl_msg_hdr_init_req(&req.ctrl_hdr, mctp_next_iid(op->ctx),
				   MCTP_CTRL_CMD_ALLOCATE_ENDPOINT_IDS);
	req.alloc_eid_op =
		(uint8_t)(mctp_ctrl_cmd_allocate_eids_alloc_eids & 0x03);
	req.pool_size = peer->pool_size;
	req.start_eid = peer->pool_start;

	/* pools are only allocated while enumerating a bridge */
	pending_op_set_step_policy(op, true, false);
	rc = pending_op_launch_step_eid(op, peer->eid, peer->net,
					STEP_ALLOCATE_ENDPOINT_IDS, &req,
					sizeof(req), op_after_allocate_eids);
	if (rc < 0) {
		/* setup failure before send — roll back gw routes like the
		 * sync error path, then signal the done cb. */
		int drc = del_pool_gw_routes_ignore_aware(peer);
		if (drc < 0)
			warnx("failed to delete route for peer pool eids %d-%d %s",
			      peer->pool_start,
			      peer->pool_start + peer->pool_size - 1,
			      strerror(-drc));
		peer->pool_size = 0;
		peer->pool_start = 0;
		on_done(op, rc, NULL, 0, NULL);
	}
}

void op_after_allocate_eids(struct pending_op *op, int rc, uint8_t *resp,
				   size_t resp_len,
				   const struct sockaddr_mctp_ext *resp_addr)
{
	struct peer *peer = op->peer;
	struct mctp_ctrl_resp_allocate_eids *r = NULL;
	uint8_t allocated_pool_size = 0;
	mctp_eid_t allocated_pool_start = 0;
	uint8_t req_pool_size = peer->pool_size;
	mctp_eid_t req_start = peer->pool_start;
	const char *fail_reason = NULL;
	uint8_t stat;

	/* Decode the AllocateEndpointIDs response — mirrors
	 * endpoint_send_allocate_endpoint_ids(), including the shared
	 * mctp_ctrl_validate_response() so a 3-byte error reply yields its
	 * completion code (-ENOTSUP / -ECONNREFUSED) rather than -ENOMSG. */
	if (rc == 0)
		rc = op_validate_response(op, resp, resp_len, resp_addr,
					  sizeof(*r), peer_tostr_short(peer),
					  MCTP_CTRL_CMD_ALLOCATE_ENDPOINT_IDS);
	if (rc == 0) {
		r = (void *)resp;
		stat = r->status & 0x03;
		if (stat == 0x00) {
			if (peer->ctx->verbose)
				fprintf(stderr, "Allocation accepted\n");
			if (r->eid_pool_size != req_pool_size ||
			    r->eid_set != req_start) {
				warnx("Unexpected pool start %d pool size %d",
				      r->eid_set, r->eid_pool_size);
				fail_reason =
					"endpoint allocated an unexpected EID pool";
				rc = -EPROTO;
			}
		} else if (stat == 0x1) {
			warnx("Allocation was rejected: already allocated by other bus"
			      " pool size %d, pool start %d",
			      r->eid_pool_size, r->eid_set);
		}
		if (rc == 0) {
			if (peer->ctx->verbose)
				fprintf(stderr,
					"Allocated size of %d, starting from EID %d\n",
					r->eid_pool_size, r->eid_set);
			allocated_pool_size = r->eid_pool_size;
			allocated_pool_start = r->eid_set;
		}
	}
	op_report_discovery_failure(op, peer->phys.ifindex,
				    MCTP_CTRL_CMD_ALLOCATE_ENDPOINT_IDS,
				    peer->eid, rc, resp, resp_len, resp_addr,
				    fail_reason);
	free(resp);

	if (rc) {
		warnx("%s failed to allocate endpoints, returned %s %d\n",
		      __func__, strerror(-rc), rc);
		int drc = del_pool_gw_routes_ignore_aware(peer);
		if (drc < 0)
			warnx("failed to delete route for peer pool eids %d-%d %s",
			      peer->pool_start,
			      peer->pool_start + peer->pool_size - 1,
			      strerror(-drc));
		peer->pool_size = 0;
		peer->pool_start = 0;
		op->rt_done_cb(op, 0, NULL, 0, NULL);
		return;
	}

	peer->pool_size = allocated_pool_size;
	peer->pool_start = allocated_pool_start;

	sd_bus_add_object_vtable(peer->ctx->bus, &peer->slot_bridge, peer->path,
				 CC_MCTP_DBUS_IFACE_BRIDGE, bus_endpoint_bridge,
				 peer);
	rc = sd_bus_emit_interfaces_added(peer->ctx->bus, peer->path,
					  CC_MCTP_DBUS_IFACE_BRIDGE, NULL);
	if (rc < 0)
		warnx("Failed to emit add %s signal for endpoint %d : %s",
		      CC_MCTP_DBUS_IFACE_BRIDGE, peer->eid, strerror(-rc));

	if (peer->ctx->verbose)
		fprintf(stderr,
			"Bridge (eid %d) assigned pool [%d, %d], size %d\n",
			peer->eid, peer->pool_start,
			peer->pool_start + peer->pool_size - 1, peer->pool_size);

	/* Poll for downstream endpoint accessibility, or schedule the
	 * settle timer that later runs query_routing_table — identical to
	 * endpoint_allocate_eids. These are already event-loop deferred and
	 * never block the dispatcher. */
	if (peer->ctx->endpoint_poll) {
		bridge_poll_start(peer);
	} else {
		uint64_t now_usec, timer_usec;
		if (sd_event_now(peer->ctx->event, CLOCK_MONOTONIC, &now_usec) <
		    0) {
			warnx("Failed to get current time");
		} else {
			timer_usec =
				now_usec + BRIDGE_SETTLE_DELAY_SEC * 1000000ULL;
			rc = sd_event_add_time(peer->ctx->event,
					       &peer->bridge_settle_timer,
					       CLOCK_MONOTONIC, timer_usec, 0,
					       cb_populate_pool_eids, peer);
			if (rc < 0)
				warnx("Failed to add timer for bridge settle: %s",
				      strerror(-rc));
		}
	}

	op->rt_done_cb(op, 0, NULL, 0, NULL);
}

/* ---------------- async query_routing_table loop --------------------
 *
 * Fragments are fetched by chained STEP_GET_ROUTING_TABLE_ENTRIES steps
 * and processed by rt_process_fragment(); once none remain, the pool is
 * finalized and rt_done_cb is invoked. */
void routing_table_loop_start(struct pending_op *op, struct peer *peer,
				     op_step_cb_t on_done)
{
	op->rt_pool_peer = peer;
	op->rt_done_cb = on_done;
	op->rt_next_handle = 0;
	op->rt_iter = 0;
	op->rt_is_static_pool_bridge = false;
	op->rt_active_pool_eid = NULL;
	op->rt_local_routing = NULL;

	if (peer->pool_size == 0 &&
	    GET_ENDPOINT_TYPE(peer->endpoint_type) == MCTP_BUS_OWNER_BRIDGE) {
		// We don't know eid pool space for the Bridge (Static EID pool), need to rely on routing table data
		// temporary set pool range to the valid allocatable unicast range
		peer->pool_size = eid_alloc_max - eid_alloc_min + 1;
		peer->pool_start = eid_alloc_min;
		op->rt_is_static_pool_bridge = true;
	}

	if (!eid_pool_range_is_valid(peer->pool_start, peer->pool_size)) {
		warnx("%s Invalid pool range start %d size %d", __func__,
		      peer->pool_start, peer->pool_size);
		if (op->rt_is_static_pool_bridge) {
			peer->pool_size = 0;
			peer->pool_start = 0;
		}
		on_done(op, -EINVAL, NULL, 0, NULL);
		return;
	}

	if (!peer->pool_size) {
		warnx(" %s Not a Bridge peer, pool size = %d", __func__,
		      peer->pool_size);
		on_done(op, -1, NULL, 0, NULL);
		return;
	}

	op->rt_active_pool_eid =
		calloc(peer->pool_size, sizeof(*op->rt_active_pool_eid));
	op->rt_local_routing =
		calloc(peer->pool_size, sizeof(*op->rt_local_routing));
	if (!op->rt_active_pool_eid || !op->rt_local_routing) {
		/* OOM: abort the walk before the first fragment is sent so the
		 * fragment callbacks never index a NULL accumulation buffer. */
		warnx("%s: OOM allocating routing accumulation buffers", __func__);
		free(op->rt_local_routing);
		op->rt_local_routing = NULL;
		free(op->rt_active_pool_eid);
		op->rt_active_pool_eid = NULL;
		if (op->rt_is_static_pool_bridge &&
		    peer->pool_start == eid_alloc_min) {
			peer->pool_size = 0;
			peer->pool_start = 0;
		}
		on_done(op, -ENOMEM, NULL, 0, NULL);
		return;
	}

	int rc = routing_table_launch_fragment(op);
	if (rc < 0) {
		/* setup failure: free buffers, restore pool, signal done */
		free(op->rt_local_routing);
		op->rt_local_routing = NULL;
		free(op->rt_active_pool_eid);
		op->rt_active_pool_eid = NULL;
		if (op->rt_is_static_pool_bridge &&
		    peer->pool_start == eid_alloc_min) {
			peer->pool_size = 0;
			peer->pool_start = 0;
		}
		on_done(op, rc, NULL, 0, NULL);
	}
}

int routing_table_launch_fragment(struct pending_op *op)
{
	struct peer *peer = op->rt_pool_peer;
	struct mctp_ctrl_cmd_get_routing_table req;

	memset(&req, 0, sizeof(req));
	req.ctrl_hdr.rq_dgram_inst = RQDI_REQ | mctp_next_iid(op->ctx);
	req.ctrl_hdr.command_code = MCTP_CTRL_CMD_GET_ROUTING_TABLE_ENTRIES;
	req.entry_handle = op->rt_next_handle;

	pending_op_set_step_policy(op, false, false);
	return pending_op_launch_step_eid(op, peer->eid, peer->net,
					  STEP_GET_ROUTING_TABLE_ENTRIES, &req,
					  sizeof(req),
					  op_after_get_routing_table_entry);
}

void
op_after_get_routing_table_entry(struct pending_op *op, int rc, uint8_t *resp,
				 size_t resp_len,
				 const struct sockaddr_mctp_ext *resp_addr)
{
	struct peer *peer = op->rt_pool_peer;
	struct mctp_ctrl_resp_get_routing_table *r = NULL;
	struct link *link;
	uint8_t next_handle = 0xFF;
	const unsigned int max_iter = 256;
	uint8_t requested_handle = op->rt_next_handle;

	if (rc < 0)
		goto fail;

	/* Cap pagination at 256 iterations and return -EPROTO on
	 * overrun, so a bridge that never reports end-of-table can't flood
	 * the loop indefinitely. */
	if (++op->rt_iter > max_iter) {
		warnx("WARNING: %s pagination exceeded %u iterations; aborting",
		      __func__, max_iter);
		rc = -EPROTO;
		goto fail;
	}

	/* Shared validation (IID, opcode, completion code, and every
	 * entry's length against the fragment size) as the sync helper. */
	rc = mctp_ctrl_validate_get_routing_table_response(
		resp, resp_len, peer_tostr_short(peer), op->iid,
		(struct sockaddr_mctp_ext *)resp_addr, op->step_suppress);
	if (rc)
		goto fail;
	r = (void *)resp;

	if (peer->ctx->verbose)
		fprintf(stderr,
			"%s: eid %d handle 0x%x returned %x entries, next handle 0x%x\n",
			__func__, peer->eid, requested_handle,
			r->number_of_entries, r->next_entry_handle);

	next_handle = r->next_entry_handle;
	rt_process_fragment(peer, r, op->rt_active_pool_eid,
			    op->rt_local_routing);
	free(resp);
	resp = NULL;

	if (next_handle != 0xFF) {
		/* A bridge that returns 0 after we've already started
		 * paginating (or repeats the same handle) would restart the
		 * loop from 0 and flood indefinitely; treat as end-of-table. */
		if ((next_handle == 0 && requested_handle != 0) ||
		    (next_handle == requested_handle)) {
			warnx("eid %d: unexpected routing table handle 0x%x (requested 0x%x) after %u iterations",
			      peer->eid, next_handle, requested_handle,
			      op->rt_iter);
			rc = -ERANGE;
			goto fail_nofree;
		}
		op->rt_next_handle = next_handle;
		rc = routing_table_launch_fragment(op);
		if (rc < 0)
			goto fail_nofree;
		return;
	}

	/* All fragments collected — finalize the pool asynchronously. The
	 * buffers are handed off to the finalize state; the temporary
	 * static-pool-size restore and rt_done_cb invocation happen in
	 * rt_finalize_pool_complete once the whole pool is processed. */
	{
		bool *active = op->rt_active_pool_eid;
		struct get_routing_table_entry **routing = op->rt_local_routing;

		op->rt_active_pool_eid = NULL;
		op->rt_local_routing = NULL;
		link = mctp_nl_get_link_userdata(peer->ctx->nl,
						 peer->phys.ifindex);
		rt_finalize_pool_async(op, peer, peer->net, &peer->phys,
				       op->rt_is_static_pool_bridge, active,
				       routing, link, op->rt_done_cb);
	}
	return;

fail:
	free(resp);
fail_nofree:
	warnx("%s: eid %d failed to get routing table data for handle 0x%x: %s",
	      __func__, peer->eid, op->rt_next_handle, strerror(-rc));
	/* free per-fragment buffers (rt entries copied so far) */
	if (op->rt_local_routing) {
		for (uint8_t idx = 0; idx < peer->pool_size; idx++)
			free(op->rt_local_routing[idx]);
		free(op->rt_local_routing);
		op->rt_local_routing = NULL;
	}
	free(op->rt_active_pool_eid);
	op->rt_active_pool_eid = NULL;
	if (op->rt_is_static_pool_bridge &&
	    peer->pool_start == eid_alloc_min) {
		peer->pool_size = 0;
		peer->pool_start = 0;
	}
	op->rt_done_cb(op, rc, NULL, 0, NULL);
}

/* Allocate a pending_op, register caller-disconnect tracker and
 * in-flight entry. Returns -EBUSY (LimitsExceeded) if a concurrent op
 * is already in flight against the same physaddr. */
int pending_op_begin(struct ctx *ctx, sd_bus_message *call,
			    sd_bus_error *berr, enum op_kind kind,
			    struct link *link, struct net *net,
			    const dest_phys *dest, uint32_t net_id,
			    struct pending_op **ret_op)
{
	struct pending_op *op = NULL;
	int rc;

	if (in_flight_find(ctx, net_id, dest->hwaddr, (uint8_t)dest->hwaddr_len,
			   link ? link->ifindex : 0)) {
		sd_bus_error_setf(
			berr, "org.freedesktop.DBus.Error.LimitsExceeded",
			"endpoint operation already in flight for this physaddr");
		return -EBUSY;
	}

	op = calloc(1, sizeof(*op));
	if (!op)
		return -ENOMEM;

	op->ctx = ctx;
	op->kind = kind;
	op->link = link;
	op->net = net;
	op->dest = *dest;
	op->sock_fd = -1;
	op->step = STEP_NONE;
	op->call = sd_bus_message_ref(call);

	rc = in_flight_register(ctx, op, net_id, link ? link->ifindex : 0);
	if (rc < 0)
		goto err;

	rc = sd_bus_track_new(ctx->bus, &op->caller_track, on_caller_gone, op);
	if (rc < 0) {
		warnx("%s: sd_bus_track_new failed: %s", __func__,
		      strerror(-rc));
		goto err;
	}
	sd_bus_track_set_recursive(op->caller_track, true);
	rc = sd_bus_track_add_sender(op->caller_track, call);
	if (rc < 0) {
		warnx("%s: sd_bus_track_add_sender failed: %s", __func__,
		      strerror(-rc));
		goto err;
	}

	*ret_op = op;
	return 0;
err:
	pending_op_cleanup(op);
	return rc;
}

/* ================= async endpoint recovery ================= */

/* ------------------------------------------------------------------ *
 * Async endpoint recovery, run from the recovery timer as a synthetic
 * pending_op (op->call == NULL) driven by STEP_RECOVER_* steps.
 *
 *   Common — responsive at the expected EID (or the UUID confirms the
 *            same device): clear degraded, emit Connectivity change,
 *            unref the recovery timer.
 *   A      — direct, EID changed, different device: UUID-by-phys
 *            (-ENOTSUP fallback uuid[15] = eid), remove_peer, then
 *            assign a fresh EID.
 *   B      — direct, EID changed, same device: UUID-by-phys, Set
 *            Endpoint ID, change_peer_eid, then the Common tail.
 *   C      — bridged, EID reclaimed by a different device: UUID-by-EID,
 *            remove_peer + add_peer, then setup_added_peer.
 *
 * There is no sd_bus_message, so terminal edges use pending_op_cleanup().
 * Failures reschedule while npolls > 0, otherwise reclaim.
 * ------------------------------------------------------------------ */

void recover_reschedule(struct pending_op *op, int rc);
static void recover_reclaim(struct pending_op *op);
static void recover_common_tail(struct pending_op *op);
void recover_after_get_eid(struct pending_op *op, int rc, uint8_t *resp,
				  size_t resp_len,
				  const struct sockaddr_mctp_ext *resp_addr);
static void recover_after_uuid_phys(struct pending_op *op, int rc,
				    uint8_t *resp, size_t resp_len,
				    const struct sockaddr_mctp_ext *resp_addr);
static void recover_after_uuid_eid(struct pending_op *op, int rc, uint8_t *resp,
				   size_t resp_len,
				   const struct sockaddr_mctp_ext *resp_addr);
static void recover_after_set_eid(struct pending_op *op, int rc, uint8_t *resp,
				  size_t resp_len,
				  const struct sockaddr_mctp_ext *resp_addr);
static void endpoint_assign_eid_async(struct pending_op *op,
				      const dest_phys *dest);
static void recover_bridged_setup_done(struct pending_op *op, int rc,
				       uint8_t *resp, size_t resp_len,
				       const struct sockaddr_mctp_ext *resp_addr);

/* Recovery steps validate their responses through the shared
 * op_validate_response() (mctp_ctrl_validate_response()), so the decode is
 * byte-for-byte with the sync query_* helpers. */
static int recover_validate_resp(struct pending_op *op, uint8_t *resp,
				 size_t resp_len,
				 const struct sockaddr_mctp_ext *resp_addr,
				 size_t exp_size, uint8_t cmd)
{
	return op_validate_response(op, resp, resp_len, resp_addr, exp_size,
				    dest_phys_tostr(&op->dest), cmd);
}

/* Sync `reschedule:` label. Re-arm the recovery poll when polls remain,
 * otherwise (or on a re-arm failure) reclaim the peer. Terminates the
 * synthetic op via pending_op_cleanup(). */
void recover_reschedule(struct pending_op *op, int rc)
{
	struct peer *peer = op->peer;

	if (peer->recovery.npolls > 0) {
		rc = mctp_ops.sd_event.source_set_time_relative(
			peer->recovery.source, peer->recovery.delay);
		if (rc >= 0)
			rc = sd_event_source_set_enabled(peer->recovery.source,
							 SD_EVENT_ONESHOT);
	}
	if (rc < 0) {
		/* Sync `reclaim:` — recovery unsuccessful, clean up the peer. */
		assert(sd_event_source_get_enabled(peer->recovery.source,
						   NULL) == 0);
		remove_peer(peer);
		op->peer = NULL;
	}
	pending_op_cleanup(op);
}

/* Sync `goto reclaim` — unconditional peer removal (used for the
 * change_peer_eid failure edge in branch B). */
static void recover_reclaim(struct pending_op *op)
{
	struct peer *peer = op->peer;

	assert(sd_event_source_get_enabled(peer->recovery.source, NULL) == 0);
	remove_peer(peer);
	op->peer = NULL;
	pending_op_cleanup(op);
}

/* Common tail: the device is present at the expected EID (or confirmed to
 * be the same device). Clear degraded, emit the Connectivity change and
 * tear down the recovery timer. */
static void recover_common_tail(struct pending_op *op)
{
	struct ctx *ctx = op->ctx;
	struct peer *peer = op->peer;
	const char *peer_path;
	int rc;

	peer->degraded = false;

	peer_path = path_from_peer(peer);
	if (!peer_path) {
		recover_reschedule(op, 0);
		return;
	}

	rc = sd_bus_emit_properties_changed(ctx->bus, peer_path,
					    CC_MCTP_DBUS_IFACE_ENDPOINT,
					    "Connectivity", NULL);
	if (rc < 0) {
		recover_reschedule(op, rc);
		return;
	}

	assert(sd_event_source_get_enabled(peer->recovery.source, NULL) == 0);
	sd_event_source_unref(peer->recovery.source);
	peer->recovery.delay = 0;
	peer->recovery.source = NULL;
	peer->recovery.npolls = 0;

	pending_op_cleanup(op);
}

/* Probe response: Get Endpoint ID. Decide which branch to take. */
void recover_after_get_eid(struct pending_op *op, int rc, uint8_t *resp,
				  size_t resp_len,
				  const struct sockaddr_mctp_ext *resp_addr)
{
	struct peer *peer = op->peer;
	const struct mctp_ctrl_resp_get_eid *r;
	struct mctp_ctrl_cmd_get_uuid req;

	(void)resp_addr;

	if (rc < 0) {
		free(resp);
		recover_reschedule(op, rc);
		return;
	}
	rc = recover_validate_resp(op, resp, resp_len, resp_addr,
				   sizeof(struct mctp_ctrl_resp_get_eid),
				   MCTP_CTRL_CMD_GET_ENDPOINT_ID);
	if (rc < 0) {
		free(resp);
		recover_reschedule(op, rc);
		return;
	}
	r = (const void *)resp;
	peer->recovery.eid = r->eid;
	peer->recovery.endpoint_type = r->eid_type;
	peer->recovery.medium_spec = r->medium_data;
	free(resp);

	/* Branch A/B — direct endpoint that answered with an unexpected EID:
	 * check the UUID by physical address to see whether it is still the
	 * same device. */
	if (peer->recovery.eid != peer->eid && peer->is_direct_endpoint) {
		mctp_ctrl_msg_hdr_init_req(&req.ctrl_hdr, mctp_next_iid(op->ctx),
					   MCTP_CTRL_CMD_GET_ENDPOINT_UUID);
		rc = pending_op_launch_step_phys(op, STEP_RECOVER_UUID, &req,
						 sizeof(req),
						 recover_after_uuid_phys);
		if (rc < 0)
			recover_reschedule(op, rc);
		return;
	}

	/* Branch C — bridged endpoint that answered at the expected EID: the
	 * bridge may have reassigned the reclaimed EID to a different device.
	 * Query the UUID by EID (not phys) to avoid the bridge's own UUID. */
	if (peer->recovery.eid == peer->eid && !peer->is_direct_endpoint) {
		mctp_ctrl_msg_hdr_init_req(&req.ctrl_hdr, mctp_next_iid(op->ctx),
					   MCTP_CTRL_CMD_GET_ENDPOINT_UUID);
		rc = pending_op_launch_step_eid(op, peer->eid, peer->net,
						STEP_RECOVER_UUID, &req,
						sizeof(req),
						recover_after_uuid_eid);
		if (rc < 0)
			recover_reschedule(op, rc);
		return;
	}

	/* Common — device is responsive at the expected EID. */
	recover_common_tail(op);
}

/* Branch A/B UUID-by-phys response. Same-device -> re-assign (B);
 * different device -> fresh async assign (A). */
static void recover_after_uuid_phys(struct pending_op *op, int rc,
				    uint8_t *resp, size_t resp_len,
				    const struct sockaddr_mctp_ext *resp_addr)
{
	static const uint8_t nil_uuid[16] = { 0 };
	struct peer *peer = op->peer;
	uint8_t uuid[16] = { 0 };
	bool uuid_matches_peer = false;
	bool uuid_matches_nil = false;
	const struct mctp_ctrl_resp_get_uuid *r;
	struct mctp_ctrl_cmd_set_eid sreq = { 0 };
	dest_phys phys;

	(void)resp_addr;

	if (rc == 0) {
		rc = recover_validate_resp(
			op, resp, resp_len, resp_addr,
			sizeof(struct mctp_ctrl_resp_get_uuid),
			MCTP_CTRL_CMD_GET_ENDPOINT_UUID);
		if (rc == 0) {
			r = (const void *)resp;
			memcpy(uuid, r->uuid, 16);
		}
	}
	free(resp);

	/* Byte-for-byte with the sync body: -ENOTSUP -> fake UUID
	 * (uuid[15] = eid); any other error keeps rc < 0, which the guard
	 * below treats as "not known to be the same device". */
	if (rc == -ENOTSUP) {
		uuid[15] = peer->eid;
		rc = 0;
	}
	if (!rc && peer->uuid) {
		static_assert(sizeof(uuid) == sizeof(nil_uuid),
			      "Unsynchronized UUID sizes");
		uuid_matches_peer = memcmp(uuid, peer->uuid, sizeof(uuid)) == 0;
		uuid_matches_nil = memcmp(uuid, nil_uuid, sizeof(uuid)) == 0;
	}

	if (rc || !uuid_matches_peer ||
	    (uuid_matches_nil && !MCTPD_RECOVER_NIL_UUID)) {
		/* Branch A — not known to be the same device: drop the old
		 * peer and run a fresh async assign for the swapped-in one. */
		phys = peer->phys;
		assert(sd_event_source_get_enabled(peer->recovery.source,
						   NULL) == 0);
		remove_peer(peer);
		op->peer = NULL;
		endpoint_assign_eid_async(op, &phys);
		return;
	}

	/* Branch B — confirmed same device: re-apply its allocated EID. */
	mctp_ctrl_msg_hdr_init_req(&sreq.ctrl_hdr, mctp_next_iid(op->ctx),
				   MCTP_CTRL_CMD_SET_ENDPOINT_ID);
	sreq.operation = mctp_ctrl_cmd_set_eid_set_eid;
	sreq.eid = peer->eid;
	rc = pending_op_launch_step_phys(op, STEP_RECOVER_SET_EID, &sreq,
					 sizeof(sreq), recover_after_set_eid);
	if (rc < 0)
		recover_reschedule(op, rc);
}

/* Branch B Set Endpoint ID response. Mirrors endpoint_send_set_endpoint_id()
 * decode; change_peer_eid when the reported EID differs; Common tail. */
static void recover_after_set_eid(struct pending_op *op, int rc, uint8_t *resp,
				  size_t resp_len,
				  const struct sockaddr_mctp_ext *resp_addr)
{
	struct peer *peer = op->peer;
	const struct mctp_ctrl_resp_set_eid *r;
	mctp_eid_t new_eid;
	uint8_t stat;

	(void)resp_addr;

	if (rc < 0) {
		free(resp);
		recover_reschedule(op, rc);
		return;
	}
	rc = recover_validate_resp(op, resp, resp_len, resp_addr,
				   sizeof(struct mctp_ctrl_resp_set_eid),
				   MCTP_CTRL_CMD_SET_ENDPOINT_ID);
	if (rc < 0) {
		free(resp);
		recover_reschedule(op, rc);
		return;
	}
	r = (const void *)resp;
	stat = r->status >> 4 & 0x3;
	new_eid = r->eid_set;

	if (stat == 0x01) {
		if (!mctp_eid_is_valid_unicast(new_eid)) {
			warnx("%s rejected assignment eid %d, and reported invalid eid %d",
			      dest_phys_tostr(&peer->phys), peer->eid, new_eid);
			free(resp);
			recover_reschedule(op, -ECONNREFUSED);
			return;
		}
	} else if (stat == 0x00) {
		if (!mctp_eid_is_valid_unicast(new_eid)) {
			warnx("%s eid %d replied with invalid eid %d, but 'accepted'",
			      dest_phys_tostr(&peer->phys), peer->eid, new_eid);
			free(resp);
			recover_reschedule(op, -ECONNREFUSED);
			return;
		} else if (new_eid != peer->eid) {
			warnx("%s eid %d replied with different eid %d, but 'accepted'",
			      dest_phys_tostr(&peer->phys), peer->eid, new_eid);
		}
	} else {
		warnx("%s unexpected status 0x%02x", dest_phys_tostr(&peer->phys),
		      r->status);
	}
	free(resp);

	if (new_eid != peer->eid) {
		rc = change_peer_eid(peer, new_eid);
		if (rc < 0) {
			recover_reclaim(op);
			return;
		}
		/* change_peer_eid() leaves the peer unpublished; the object
		 * path moves with the EID. The properties were queried when
		 * the peer was first set up, so publishing here re-registers
		 * the full interface set. */
		rc = publish_peer(peer, true);
		if (rc < 0) {
			recover_reschedule(op, rc);
			return;
		}
	}

	recover_common_tail(op);
}

/* Branch A — allocate_eid / add_peer bookkeeping, then Set Endpoint ID,
 * then the same tail as SetupEndpoint (op_after_set_endpoint_id ->
 * dispatch_setup_added_peer_async -> assign_after_qpp_done). */
static void endpoint_assign_eid_async(struct pending_op *op,
				      const dest_phys *dest)
{
	struct ctx *ctx = op->ctx;
	sd_bus_error berr = SD_BUS_ERROR_NULL;
	struct peer *new_peer = NULL;
	struct mctp_ctrl_cmd_set_eid req = { 0 };
	int rc;

	rc = endpoint_assign_prepare_peer(ctx, &berr, dest, 0,
					  /*assign_bridge=*/false, &new_peer);
	sd_bus_error_free(&berr);
	if (rc < 0) {
		/* The old peer is already gone; nothing to reschedule. */
		pending_op_cleanup(op);
		return;
	}

	op->dest = *dest;
	pending_op_set_peer(op, new_peer);

	mctp_ctrl_msg_hdr_init_req(&req.ctrl_hdr, mctp_next_iid(ctx),
				   MCTP_CTRL_CMD_SET_ENDPOINT_ID);
	req.operation = mctp_ctrl_cmd_set_eid_set_eid;
	req.eid = new_peer->eid;
	rc = pending_op_launch_step_phys(op, STEP_RECOVER_ASSIGN_SET_EID, &req,
					 sizeof(req), op_after_set_endpoint_id);
	if (rc < 0)
		pending_op_reply_error(op, rc);
}

/* Branch C setup tail — mirrors setup_added_peer(): publish on success,
 * remove_peer on failure. Terminal cleanup for the synthetic op. */
static void recover_bridged_setup_done(struct pending_op *op, int rc,
				       uint8_t *resp, size_t resp_len,
				       const struct sockaddr_mctp_ext *resp_addr)
{
	struct peer *peer = op->peer;

	(void)resp;
	(void)resp_len;
	(void)resp_addr;

	if (rc < 0) {
		if (op->peer) {
			remove_peer(op->peer);
			op->peer = NULL;
		}
		pending_op_cleanup(op);
		return;
	}

	rc = publish_peer(peer, true);
	if (rc < 0) {
		remove_peer(peer);
		op->peer = NULL;
		pending_op_cleanup(op);
		return;
	}

	pending_op_cleanup(op);
}

/* Branch C UUID-by-EID response. Different device -> remove + add + async
 * re-discovery; same device -> Common tail. */
static void recover_after_uuid_eid(struct pending_op *op, int rc, uint8_t *resp,
				   size_t resp_len,
				   const struct sockaddr_mctp_ext *resp_addr)
{
	static const uint8_t nil_uuid[16] = { 0 };
	struct ctx *ctx = op->ctx;
	struct peer *peer = op->peer;
	uint8_t uuid[16] = { 0 };
	bool uuid_matches_peer = false;
	bool uuid_matches_nil = false;
	const struct mctp_ctrl_resp_get_uuid *r;
	struct peer *new_peer = NULL;
	dest_phys phys;
	mctp_eid_t new_eid;
	uint32_t new_net;

	(void)resp_addr;

	if (rc == 0) {
		rc = recover_validate_resp(
			op, resp, resp_len, resp_addr,
			sizeof(struct mctp_ctrl_resp_get_uuid),
			MCTP_CTRL_CMD_GET_ENDPOINT_UUID);
		if (rc == 0) {
			r = (const void *)resp;
			memcpy(uuid, r->uuid, 16);
		}
	}
	free(resp);

	if (rc == -ENOTSUP) {
		uuid[15] = peer->eid;
		rc = 0;
	}
	if (rc) {
		/* Sync: unusable EID — remove the peer and stop (no reschedule). */
		assert(sd_event_source_get_enabled(peer->recovery.source,
						   NULL) == 0);
		remove_peer(peer);
		op->peer = NULL;
		pending_op_cleanup(op);
		return;
	}
	if (peer->uuid) {
		static_assert(sizeof(uuid) == sizeof(nil_uuid),
			      "Unsynchronized UUID sizes");
		uuid_matches_peer = memcmp(uuid, peer->uuid, sizeof(uuid)) == 0;
		uuid_matches_nil = memcmp(uuid, nil_uuid, sizeof(uuid)) == 0;
	}

	if (!uuid_matches_peer ||
	    (uuid_matches_nil && !MCTPD_RECOVER_NIL_UUID)) {
		/* Branch C — the reclaimed EID now belongs to a different
		 * device: emit remove for the old peer, add the new one, and
		 * re-discover it asynchronously. */
		assert(sd_event_source_get_enabled(peer->recovery.source,
						   NULL) == 0);
		phys = peer->phys;
		new_eid = peer->eid;
		new_net = peer->net;
		remove_peer(peer);
		op->peer = NULL;

		rc = add_peer(ctx, &phys, new_eid, new_net, &new_peer, true);
		if (rc) {
			warnx("can't add peer: %s", strerror(-rc));
			pending_op_cleanup(op);
			return;
		}
		op->peer = new_peer;
		op->dest = phys;
		dispatch_setup_added_peer_async(op, new_peer,
						recover_bridged_setup_done);
		return;
	}

	/* Same device — fall through to the Common tail. */
	recover_common_tail(op);
}

/* ================= pool populate continuation ================= */

/* BMC-as-bridge: replay any cached routing-info entries to the freshly
 * populated bridge as Routing Info Update messages. This must run after
 * the async routing-table walk and pool finalize so the local peer table
 * is updated before these outbound bridge updates go out. */
void bridge_send_cached_routing_updates(struct peer *peer)
{
	uint8_t bridge_bmc_eid = peer->ctx->bmc_bridge_eid;

	/* BMC as bridge not enabled. */
	if (!bridge_bmc_eid)
		return;

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
		int rc;

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
}

void populate_pool_done(struct pending_op *op, int rc, uint8_t *resp,
			       size_t resp_len,
			       const struct sockaddr_mctp_ext *resp_addr)
{
	(void)resp;
	(void)resp_len;
	(void)resp_addr;

	if (rc < 0 && op->ctx->verbose)
		warnx("Failed to get Routing Table information\n");

	/* Outbound bridge Routing Info Updates run here, after the
	 * routing-table walk and pool finalize populated the local peer
	 * table. */
	if (op->peer)
		bridge_send_cached_routing_updates(op->peer);

	pending_op_cleanup(op);
}

/* ---------------- async rt_finalize_pool ----------------------------
 *
 * Walks the pool one EID at a time: inactive-peer removal and add_peer
 * run inline, and each active EID's properties are fetched via
 * qpp_start(). A per-EID failure removes that peer and moves on. The
 * finalize_* fields are separate from rt_* because the nested
 * STEP_QPP_ROUTING_DATA step reuses rt_pool_peer / rt_next_handle. */
void rt_finalize_pool_complete(struct pending_op *op)
{
	struct peer *bridge = op->finalize_bridge;
	int rc;

	/* Free the per-fragment buffers (entries not consumed by add_peer). */
	if (op->finalize_routing) {
		for (uint8_t idx = 0; idx < op->finalize_pool_size; idx++)
			free(op->finalize_routing[idx]);
		free(op->finalize_routing);
		op->finalize_routing = NULL;
	}
	free(op->finalize_active);
	op->finalize_active = NULL;

	/* Bridge service-state transition (was the tail of rt_finalize_pool). */
	if (op->finalize_link &&
	    op->finalize_link->service_state == SERVICE_STATE_STARTING) {
		op->finalize_link->service_state = SERVICE_STATE_ENABLED;
		rc = sd_bus_emit_properties_changed(
			bridge->ctx->bus, op->finalize_link->path,
			OPENBMC_SERVICE_READINESS_IFACE, "State", NULL);
		if (rc < 0)
			warnx("%s: Service state change emit failed: %d %s",
			      __func__, rc, strerror(-rc));
	}

	/* Restore the bridge's temporary static-pool sizing, matching the
	 * post-rt_finalize_pool restore in the sync query_routing_table. */
	if (op->finalize_static_pool && bridge->pool_start == eid_alloc_min) {
		bridge->pool_size = 0;
		bridge->pool_start = 0;
	}

	/* Restore the working peer and hand back to the outer continuation. */
	op->peer = op->finalize_saved_peer;
	op->finalize_done_cb(op, 0, NULL, 0, NULL);
}

/* Resume point after each per-EID property fetch: apply the sync
 * rt_finalize_pool post-query bookkeeping for the current EID, then advance
 * to the next pool index. */
void finalize_after_qpp_done(struct pending_op *op, int rc,
				    uint8_t *resp, size_t resp_len,
				    const struct sockaddr_mctp_ext *resp_addr)
{
	struct peer *peer = op->peer;
	struct peer *bridge = op->finalize_bridge;

	(void)resp;
	(void)resp_len;
	(void)resp_addr;

	if (op->finalize_cur_new) {
		/* Freshly add_peer'd active EID: publish on success, remove on
		 * failure (mirrors setup_added_peer's remove-on-error tail and
		 * rt_finalize_pool's "continue" on setup failure). */
		if (rc < 0) {
			warnx("%s failed to setup peer for active eid %d: %d %s",
			      __func__, peer ? peer->eid : 0, rc, strerror(-rc));
			if (peer)
				remove_peer(peer);
		} else {
			rc = publish_peer(peer, true);
			if (rc < 0) {
				warnx("%s failed to publish peer for active eid %d: %d %s",
				      __func__, peer->eid, rc, strerror(-rc));
				remove_peer(peer);
			} else if (bridge->ctx->verbose) {
				fprintf(stderr, "created new endpoint %d\n",
					peer->eid);
			}
		}
	} else {
		/* Existing active EID refresh: emit Connectivity changed, exactly
		 * as the sync rt_finalize_pool existing-peer branch did after
		 * query_peer_properties. Errors are warn-and-continue. */
		if (rc < 0)
			warnx("%s: query_peer_properties failed: %d %s", __func__,
			      rc, strerror(-rc));
		if (peer) {
			const char *peer_path = path_from_peer(peer);
			if (peer_path) {
				int erc = sd_bus_emit_properties_changed(
					peer->ctx->bus, peer_path,
					CC_MCTP_DBUS_IFACE_ENDPOINT,
					"Connectivity", NULL);
				if (erc < 0)
					warnx("%s: Connectivity change emit failed: %d %s",
					      __func__, erc, strerror(-erc));
			} else {
				warnx("%s: no path to peer exists", __func__);
			}
		}
	}

	op->finalize_idx++;
	rt_finalize_process_next(op);
}

/* Walk the pool from op->finalize_idx, handling non-wire cases inline and
 * launching one async property fetch per active EID that needs one. Returns
 * (via the async chain) to finalize_after_qpp_done for each fetch; calls
 * rt_finalize_pool_complete when the whole pool has been processed. */
void rt_finalize_process_next(struct pending_op *op)
{
	struct peer *bridge = op->finalize_bridge;
	int net = op->finalize_net;
	bool *active = op->finalize_active;
	struct get_routing_table_entry **local_routing = op->finalize_routing;
	struct ctx *ctx = bridge->ctx;

	if (!active) {
		rt_finalize_pool_complete(op);
		return;
	}

	while (op->finalize_idx < op->finalize_pool_size) {
		uint8_t index = op->finalize_idx;
		mctp_eid_t eid = index + op->finalize_pool_start;
		struct peer *existing_peer = find_peer_by_addr(ctx, eid, net);

		if (active[index]) {
			if (!existing_peer) {
				/* Active EID not present locally — create it. */
				struct peer *allocated_peer = NULL;
				struct net *n;
				int rc = add_peer(ctx, &op->finalize_dest, eid,
						  net, &allocated_peer, true);
				if (rc < 0) {
					warnx("%s failed to add peer for active eid %d: %d %s",
					      __func__, eid, rc, strerror(-rc));
					op->finalize_idx++;
					continue;
				}

				allocated_peer->routing_table_entry =
					local_routing[index];
				local_routing[index] = NULL;
				/* Copy ignore message types from the bridge; on
				 * OOM drop the new peer and advance. */
				if (bridge->num_ignore_message_types > 0) {
					allocated_peer->ignore_message_types =
						malloc(bridge->num_ignore_message_types);
					if (!allocated_peer->ignore_message_types) {
						warnx("%s: OOM copying ignore_message_types for eid %d",
						      __func__, eid);
						remove_peer(allocated_peer);
						op->finalize_idx++;
						continue;
					}
					memcpy(allocated_peer->ignore_message_types,
					       bridge->ignore_message_types,
					       bridge->num_ignore_message_types);
					allocated_peer->num_ignore_message_types =
						bridge->num_ignore_message_types;
				}
				if (op->finalize_static_pool) {
					peer_static_pool_mark_eid(bridge, eid);
					/* Gateway route must be in place before
					 * the property query contacts the
					 * downstream endpoint. */
					struct mctp_fq_addr gw_addr = { 0 };
					gw_addr.net = bridge->net;
					gw_addr.eid = bridge->eid;
					int gw_rc = mctp_nl_route_add(
						ctx->nl, (uint8_t)eid, 0, 0,
						&gw_addr, bridge->mtu);
					if (gw_rc < 0 && gw_rc != -EEXIST)
						warnx("Failed to add gateway route for static pool EID %d via %d: %s",
						      eid, bridge->eid,
						      strerror(-gw_rc));
				}
				allocated_peer->pool_owner_eid = bridge->eid;

				/* Replicate setup_added_peer()'s pre-query work
				 * (conditional route; the MTU is set by add_peer)
				 * inline, then run the property query async.
				 * Publish moves into finalize_after_qpp_done. */
				n = lookup_net(ctx, allocated_peer->net);
				if (n && !is_eid_in_bridge_pool(
						 n, ctx, allocated_peer->eid,
						 NULL))
					add_peer_route(allocated_peer);

				op->peer = allocated_peer;
				op->finalize_cur_new = true;
				op->step = STEP_POOL_FINALIZE;
				/* setup_added_peer(): discovery = true */
				qpp_start(op, finalize_after_qpp_done, true);
				return;
			}

			/* Active EID present locally — refresh properties
			 * (query_peer_properties(existing_peer, false)). */
			existing_peer->degraded = false;
			op->peer = existing_peer;
			op->finalize_cur_new = false;
			op->step = STEP_POOL_FINALIZE;
			qpp_start(op, finalize_after_qpp_done, false);
			return;
		}

		/* Inactive EID that exists locally — remove it (no wire). */
		if ((existing_peer && false == should_ignore_eid(bridge, eid) &&
		     !op->finalize_static_pool) ||
		    (existing_peer && op->finalize_static_pool &&
		     peer_static_pool_has_eid(bridge, eid))) {
			if (!existing_peer->degraded) {
				int rc;
				if (ctx->verbose)
					fprintf(stderr,
						"inactive endpoint, removing %d\n",
						eid);
				if (op->finalize_static_pool) {
					struct mctp_fq_addr gw_addr = { 0 };
					gw_addr.net = bridge->net;
					gw_addr.eid = bridge->eid;
					int gw_rc = mctp_nl_route_del(
						ctx->nl, (uint8_t)eid, 0, 0,
						&gw_addr);
					if (gw_rc < 0)
						warnx("Failed to remove gateway route for static pool EID %d via %d: %s",
						      eid, bridge->eid,
						      strerror(-gw_rc));
					bridge->static_pool_eids[eid] = 0;
				}
				rc = remove_peer(existing_peer);
				if (rc < 0)
					warnx("Failed to remove endpoint %d : %s",
					      eid, strerror(rc));
			}
		}
		op->finalize_idx++;
	}

	rt_finalize_pool_complete(op);
}

void rt_finalize_pool_async(
	struct pending_op *op, struct peer *peer, int net, const dest_phys *dest,
	bool is_static_pool_bridge, bool *active_pool_eid,
	struct get_routing_table_entry **local_routing, struct link *link,
	op_step_cb_t done_cb)
{
	op->finalize_bridge = peer;
	op->finalize_net = net;
	op->finalize_dest = *dest;
	op->finalize_static_pool = is_static_pool_bridge;
	op->finalize_active = active_pool_eid;
	op->finalize_routing = local_routing;
	op->finalize_link = link;
	op->finalize_pool_size = peer->pool_size;
	op->finalize_pool_start = peer->pool_start;
	op->finalize_idx = 0;
	op->finalize_cur_new = false;
	op->finalize_saved_peer = op->peer;
	op->finalize_done_cb = done_cb;

	rt_finalize_process_next(op);
}
