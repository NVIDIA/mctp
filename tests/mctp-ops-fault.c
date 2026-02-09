/* SPDX-License-Identifier: GPL-2.0 */
/*
 * mctp-ops-fault: Fault-injection ops for coverage testing.
 *
 * This replaces mctp-ops-test.c for a special test binary that exercises
 * error paths in mctpd.c by making socket operations fail on demand.
 *
 * The approach: we wrap the real test ops and add fault injection hooks.
 * When fault_next_* is set, the next call to that op will fail with the
 * specified errno, then the fault is cleared.
 */

#define _GNU_SOURCE

#include <err.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdint.h>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <linux/netlink.h>

#include "mctp-ops.h"

/* Fault injection state — set these before calling a function to make it fail.
 * NOT static: test code (test_mctpd_fault.c) sets these externally. */
int fault_mctp_socket_errno = 0;
int fault_mctp_setsockopt_errno = 0;
int fault_mctp_bind_errno = 0;
int fault_mctp_sendto_errno = 0;
int fault_mctp_sendto_short = 0;
int fault_mctp_recvfrom_errno = 0;
int fault_mctp_recvfrom_peek_len = -1;
int fault_mctp_recvfrom_data_len = -1;
int fault_mctp_recvfrom_addrlen = 0;
int fault_nl_socket_errno = 0;
int fault_nl_recvfrom_errno = 0;

/* Counters for how many times each op was called */
int call_count_mctp_socket = 0;
int call_count_mctp_sendto = 0;
int call_count_mctp_recvfrom = 0;

#define MCTP_RESP_QUEUE_SIZE 4096
static uint8_t mctp_resp_queue[MCTP_RESP_QUEUE_SIZE];
static size_t mctp_resp_queue_len = 0;
static int mctp_resp_queue_active = 0;

void mctp_mock_queue_response(const void *data, size_t len)
{
    if (len > MCTP_RESP_QUEUE_SIZE)
        len = MCTP_RESP_QUEUE_SIZE;
    memcpy(mctp_resp_queue, data, len);
    mctp_resp_queue_len = len;
    mctp_resp_queue_active = 1;
}

/* ---- MCTP socket ops with fault injection ---- */

static int fi_mctp_socket(void)
{
    call_count_mctp_socket++;
    if (fault_mctp_socket_errno) {
        int e = fault_mctp_socket_errno;
        fault_mctp_socket_errno = 0;
        errno = e;
        return -1;
    }
    /* Create a real socketpair for testing */
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) < 0)
        return -1;
    close(sv[1]); /* close remote end */
    return sv[0];
}

/* Track setsockopt calls globally for nth-call fault injection */
int setsockopt_call_count = 0;
int fault_setsockopt_fail_on_call = 0;  /* fail on Nth call (1-based), 0 = disabled */
int fault_setsockopt_fail_errno = EINVAL;

static int fi_mctp_setsockopt(int sd, int level, int optname, void *optval,
                              socklen_t optlen)
{
    setsockopt_call_count++;
    if (fault_mctp_setsockopt_errno) {
        int e = fault_mctp_setsockopt_errno;
        fault_mctp_setsockopt_errno = 0;
        errno = e;
        return -1;
    }
    if (fault_setsockopt_fail_on_call > 0 &&
        setsockopt_call_count == fault_setsockopt_fail_on_call) {
        fault_setsockopt_fail_on_call = 0;
        errno = fault_setsockopt_fail_errno;
        fault_setsockopt_fail_errno = EINVAL;
        return -1;
    }
    return 0; /* always succeed */
}

static int fi_mctp_bind(int sd, struct sockaddr *addr, socklen_t addrlen)
{
    if (fault_mctp_bind_errno) {
        int e = fault_mctp_bind_errno;
        fault_mctp_bind_errno = 0;
        errno = e;
        return -1;
    }
    return 0;
}

static ssize_t fi_mctp_sendto(int sd, const void *buf, size_t len, int flags,
                              const struct sockaddr *dest, socklen_t addrlen)
{
    call_count_mctp_sendto++;
    if (fault_mctp_sendto_errno) {
        int e = fault_mctp_sendto_errno;
        fault_mctp_sendto_errno = 0;
        errno = e;
        return -1;
    }
    if (fault_mctp_sendto_short) {
        fault_mctp_sendto_short = 0;
        return (len > 0) ? (ssize_t)(len - 1) : 0;
    }
    return (ssize_t)len; /* pretend success */
}

static ssize_t fi_mctp_recvfrom(int sd, void *buf, size_t len, int flags,
                                struct sockaddr *src, socklen_t *addrlen)
{
    call_count_mctp_recvfrom++;
    if (fault_mctp_recvfrom_errno) {
        int e = fault_mctp_recvfrom_errno;
        fault_mctp_recvfrom_errno = 0;
        errno = e;
        return -1;
    }
    if ((flags & MSG_PEEK) && fault_mctp_recvfrom_peek_len >= 0)
        return fault_mctp_recvfrom_peek_len;

    if (!(flags & MSG_PEEK) && fault_mctp_recvfrom_data_len >= 0) {
        if (addrlen && fault_mctp_recvfrom_addrlen > 0)
            *addrlen = (socklen_t)fault_mctp_recvfrom_addrlen;
        return fault_mctp_recvfrom_data_len;
    }

    if (mctp_resp_queue_active && mctp_resp_queue_len > 0) {
        size_t qlen = mctp_resp_queue_len;

        if (flags & MSG_PEEK)
            return (ssize_t)qlen;

        if (len < qlen)
            qlen = len;
        if (buf)
            memcpy(buf, mctp_resp_queue, qlen);
        if (addrlen && fault_mctp_recvfrom_addrlen > 0)
            *addrlen = (socklen_t)fault_mctp_recvfrom_addrlen;
        mctp_resp_queue_active = 0;
        mctp_resp_queue_len = 0;
        return (ssize_t)qlen;
    }

    /* Default behavior: no payload available */
    return 0;
}

static int fi_mctp_close(int sd)
{
    return close(sd);
}

/* ---- NL socket ops with fault injection ---- */

static int fi_nl_socket(void)
{
    if (fault_nl_socket_errno) {
        int e = fault_nl_socket_errno;
        fault_nl_socket_errno = 0;
        errno = e;
        return -1;
    }
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) < 0)
        return -1;
    close(sv[1]);
    return sv[0];
}

/* Track NL recvfrom calls */
static int nl_recv_call_count = 0;
/* When set, NL setsockopt fails on the nth call (1-based) */
int fault_nl_setsockopt_fail_on_call = 0;
static int nl_setsockopt_call_count = 0;
int fault_nl_recvfrom_fail_on_call = 0;
int fault_nl_recvfrom_fail_errno = EIO;
/* When set, next NL recvfrom returns NLMSG_ERROR instead of NLMSG_DONE */
int fault_nl_respond_error = 0;
int fault_nl_recvfrom_zero_once = 0;
int fault_nl_recvfrom_zero_on_call = 0;
/* Sequenced response queue: if set, return these bytes instead of default DONE */
#define NL_RESP_QUEUE_SIZE 4096
static uint8_t nl_resp_queue[NL_RESP_QUEUE_SIZE];
static size_t nl_resp_queue_len = 0;
static int nl_resp_queue_active = 0;  /* 1 = use queue, 0 = use default DONE */

void nl_mock_queue_response(const void *data, size_t len)
{
    if (len > NL_RESP_QUEUE_SIZE) len = NL_RESP_QUEUE_SIZE;
    memcpy(nl_resp_queue, data, len);
    nl_resp_queue_len = len;
    nl_resp_queue_active = 1;
}

void nl_mock_clear_queue(void)
{
    nl_resp_queue_active = 0;
    nl_resp_queue_len = 0;
}

static ssize_t fi_nl_recvfrom(int sd, void *buf, size_t len, int flags,
                              struct sockaddr *src, socklen_t *addrlen)
{
    if (fault_nl_recvfrom_errno) {
        int e = fault_nl_recvfrom_errno;
        fault_nl_recvfrom_errno = 0;
        errno = e;
        return -1;
    }
    if (fault_nl_recvfrom_zero_once) {
        fault_nl_recvfrom_zero_once = 0;
        return 0;
    }

    nl_recv_call_count++;
    if (fault_nl_recvfrom_zero_on_call > 0 &&
        nl_recv_call_count == fault_nl_recvfrom_zero_on_call) {
        fault_nl_recvfrom_zero_on_call = 0;
        return 0;
    }
    if (fault_nl_recvfrom_fail_on_call > 0 &&
        nl_recv_call_count == fault_nl_recvfrom_fail_on_call) {
        fault_nl_recvfrom_fail_on_call = 0;
        errno = fault_nl_recvfrom_fail_errno;
        fault_nl_recvfrom_fail_errno = EIO;
        return -1;
    }

    /* Sequenced response: if queue is active, return queued data then clear */
    if (nl_resp_queue_active && nl_resp_queue_len > 0) {
        size_t qlen = nl_resp_queue_len;
        if (flags & MSG_PEEK) return (ssize_t)qlen;
        nl_resp_queue_active = 0;  /* consume on real recv */
        if (len < qlen) qlen = len;
        if (buf) memcpy(buf, nl_resp_queue, qlen);
        if (addrlen) {
            struct sockaddr_nl a = { .nl_family = AF_NETLINK };
            if (*addrlen >= sizeof(a) && src) memcpy(src, &a, sizeof(a));
            *addrlen = sizeof(a);
        }
        return (ssize_t)qlen;
    }

    /* When fault_nl_respond_error is set, return an NLMSG_ERROR instead */
    if (fault_nl_respond_error) {
        fault_nl_respond_error = 0;
        struct {
            struct nlmsghdr nh;
            struct nlmsgerr err;
        } err_msg;
        memset(&err_msg, 0, sizeof(err_msg));
        err_msg.nh.nlmsg_len = NLMSG_LENGTH(sizeof(struct nlmsgerr));
        err_msg.nh.nlmsg_type = NLMSG_ERROR;
        err_msg.err.error = -EPERM;
        err_msg.err.msg.nlmsg_len = NLMSG_HDRLEN;
        size_t elen = err_msg.nh.nlmsg_len;
        if (flags & MSG_PEEK) return (ssize_t)elen;
        if (len < elen) elen = len;
        if (buf) memcpy(buf, &err_msg, elen);
        if (addrlen) {
            struct sockaddr_nl a = { .nl_family = AF_NETLINK };
            if (*addrlen >= sizeof(a) && src) memcpy(src, &a, sizeof(a));
            *addrlen = sizeof(a);
        }
        return (ssize_t)elen;
    }

    /* Return a minimal NLMSG_DONE message so fill_linkmap / mctp_nl_recv_all
     * succeeds with an empty linkmap.  MSG_PEEK returns the size; the real
     * recv returns the data. */
    struct {
        struct nlmsghdr nh;
        int done_padding;
    } done_msg;
    memset(&done_msg, 0, sizeof(done_msg));
    done_msg.nh.nlmsg_len = NLMSG_LENGTH(sizeof(int));
    done_msg.nh.nlmsg_type = NLMSG_DONE; /* 0x03 */
    done_msg.nh.nlmsg_flags = 0;

    size_t msg_len = done_msg.nh.nlmsg_len;

    if (flags & MSG_PEEK) {
        /* PEEK: just return the size */
        return (ssize_t)msg_len;
    }

    /* Real recv: copy the data */
    if (len < msg_len)
        msg_len = len;
    if (buf)
        memcpy(buf, &done_msg, msg_len);
    if (addrlen) {
        struct sockaddr_nl nl_addr = { .nl_family = AF_NETLINK };
        if (*addrlen >= sizeof(nl_addr) && src)
            memcpy(src, &nl_addr, sizeof(nl_addr));
        *addrlen = sizeof(nl_addr);
    }
    return (ssize_t)msg_len;
}

static void fi_bug_warn(const char *fmt, va_list args)
{
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\n");
}

const struct mctp_ops mctp_ops = {
    .mctp = {
        .socket = fi_mctp_socket,
        .setsockopt = fi_mctp_setsockopt,
        .bind = fi_mctp_bind,
        .sendto = fi_mctp_sendto,
        .recvfrom = fi_mctp_recvfrom,
        .close = fi_mctp_close,
    },
    .nl = {
        .socket = fi_nl_socket,
        .setsockopt = fi_mctp_setsockopt,
        .bind = fi_mctp_bind,
        .sendto = fi_mctp_sendto,
        .recvfrom = fi_nl_recvfrom,
        .close = fi_mctp_close,
    },
    .bug_warn = fi_bug_warn,
};

void mctp_ops_init(void) { }
