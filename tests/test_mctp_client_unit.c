/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Unit tests for mctp-client.c helper paths.
 * Uses socket/send/recv stubs so tests run without kernel MCTP setup.
 */

#include <assert.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include "mctp-control-spec.h"

static int stub_socket_calls;
static int stub_sendto_calls;
static int stub_recvfrom_calls;
static int stub_sendto_mode;
static int stub_recv_peek_mode;
static int stub_recv_data_mode;
static int stub_socket_mode;
static int stub_malloc_mode;

static int test_socket(int domain, int type, int protocol)
{
	(void)domain;
	(void)type;
	(void)protocol;
	stub_socket_calls++;
	if (stub_socket_mode == 1)
		return -1;
	return 7;
}

static ssize_t test_sendto(int sd, const void *buf, size_t len, int flags,
			   const struct sockaddr *dest_addr, socklen_t addrlen)
{
	(void)sd;
	(void)buf;
	(void)flags;
	(void)dest_addr;
	(void)addrlen;
	stub_sendto_calls++;
	if (stub_sendto_mode == 1)
		return -1;
	if (stub_sendto_mode == 2 && len > 0)
		return (ssize_t)(len - 1);
	return (ssize_t)len;
}

static ssize_t test_recvfrom(int sd, void *buf, size_t len, int flags,
			     struct sockaddr *src_addr, socklen_t *addrlen)
{
	static const uint8_t reply[] = {0xaa, 0xbb, 0xcc};

	(void)sd;
	(void)src_addr;
	if (addrlen)
		*addrlen = 0;

	stub_recvfrom_calls++;

	if ((flags & MSG_PEEK) && !buf) {
		if (stub_recv_peek_mode == 1)
			return -1;
		return (ssize_t)sizeof(reply);
	}

	if (buf && len >= sizeof(reply)) {
		if (stub_recv_data_mode == 1)
			return -1;
		if (stub_recv_data_mode == 2)
			return (ssize_t)(sizeof(reply) - 1);
		memcpy(buf, reply, sizeof(reply));
		return (ssize_t)sizeof(reply);
	}

	return -1;
}

static void *test_malloc(size_t size)
{
	if (stub_malloc_mode == 1) {
		stub_malloc_mode = 0;
		return NULL;
	}
	return calloc(1, size);
}

#define socket test_socket
#define sendto test_sendto
#define recvfrom test_recvfrom
#define malloc test_malloc
#define main mctp_client_main
#include "mctp-client.c"
#undef main
#undef malloc

static int run_child_expect_failure(void (*fn)(void))
{
	pid_t pid = fork();
	int status = 0;

	assert(pid >= 0);
	if (pid == 0) {
		fn();
		_exit(0);
	}
	assert(waitpid(pid, &status, 0) == pid);
	return (WIFEXITED(status) && WEXITSTATUS(status) != 0) ||
	       WIFSIGNALED(status);
}

enum child_case {
	CC_CREATE_EMPTY,
	CC_CREATE_INVALID_TOKEN,
	CC_CREATE_TOO_LARGE,
	CC_CREATE_ULONG_MAX,
	CC_MAIN_INVALID_TAG,
	CC_MAIN_INVALID_EID,
	CC_MAIN_INVALID_TYPE,
	CC_SOCKET_FAIL,
	CC_SEND_FAIL,
	CC_SEND_PARTIAL,
	CC_RECV_PEEK_FAIL,
	CC_RECV_DATA_FAIL,
	CC_RECV_DATA_SHORT,
	CC_RECV_ALLOC_FAIL,
	CC_CREATE_ALLOC_FAIL,
	CC_CTRL_HDR_ASSERT,
	CC_MAIN_INVALID_NET_REPARSE,
};

static enum child_case active_child_case;

static void run_active_child_case(void)
{
	uint8_t raw[] = {0x01, 0x02};
	struct data_t payload = { .data = raw, .len = sizeof(raw) };

	stub_socket_mode = 0;
	stub_sendto_mode = 0;
	stub_recv_peek_mode = 0;
	stub_recv_data_mode = 0;

	switch (active_child_case) {
	case CC_CREATE_EMPTY: {
		char *data[] = {};
		(void)create_data(data, 0);
		break;
	}
	case CC_CREATE_INVALID_TOKEN: {
		char *data[] = {"zz"};
		(void)create_data(data, 1);
		break;
	}
	case CC_CREATE_TOO_LARGE: {
		char *data[] = {"100"};
		(void)create_data(data, 1);
		break;
	}
	case CC_CREATE_ULONG_MAX: {
		char *data[] = {"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"};
		(void)create_data(data, 1);
		break;
	}
	case CC_MAIN_INVALID_TAG: {
		char *argv[] = {"mctp-client", "foo", "1", "eid", "8", "type",
				"control", "data", "01"};
		_exit(mctp_client_main((int)(sizeof(argv) / sizeof(argv[0])),
				       argv));
	}
	case CC_MAIN_INVALID_EID: {
		char *argv[] = {"mctp-client", "eid", "300", "type", "control",
				"data", "01"};
		_exit(mctp_client_main((int)(sizeof(argv) / sizeof(argv[0])),
				       argv));
	}
	case CC_MAIN_INVALID_TYPE: {
		char *argv[] = {"mctp-client", "eid", "8", "type", "badtype",
				"data", "01"};
		_exit(mctp_client_main((int)(sizeof(argv) / sizeof(argv[0])),
				       argv));
	}
	case CC_SOCKET_FAIL:
		stub_socket_mode = 1;
		(void)do_send_recv(0, 8, 0, &payload);
		break;
	case CC_SEND_FAIL:
		stub_sendto_mode = 1;
		(void)do_send_recv(0, 8, 0, &payload);
		break;
	case CC_SEND_PARTIAL:
		stub_sendto_mode = 2;
		(void)do_send_recv(0, 8, 0, &payload);
		break;
	case CC_RECV_PEEK_FAIL:
		stub_recv_peek_mode = 1;
		(void)do_send_recv(0, 8, 0, &payload);
		break;
	case CC_RECV_DATA_FAIL:
		stub_recv_data_mode = 1;
		(void)do_send_recv(0, 8, 0, &payload);
		break;
	case CC_RECV_DATA_SHORT:
		stub_recv_data_mode = 2;
		(void)do_send_recv(0, 8, 0, &payload);
		break;
	case CC_RECV_ALLOC_FAIL:
		stub_malloc_mode = 1;
		(void)do_send_recv(0, 8, 0, &payload);
		break;
	case CC_CREATE_ALLOC_FAIL: {
		char *data[] = {"01"};
		stub_malloc_mode = 1;
		(void)create_data(data, 1);
		break;
	}
	case CC_CTRL_HDR_ASSERT: {
		struct mctp_ctrl_msg_hdr hdr = {0};
		mctp_ctrl_msg_hdr_init_req(&hdr, 0x20, 0x01);
		break;
	}
	case CC_MAIN_INVALID_NET_REPARSE: {
		/* Duplicate net tags: last wins; with stubs do_send_recv succeeds. */
		char *argv[] = {"mctp-client", "net", "300", "net", "1", "eid",
				"8", "type", "control", "data", "01"};
		_exit(mctp_client_main((int)(sizeof(argv) / sizeof(argv[0])),
				       argv));
	}
	}
}

static void test_type_lookup(void)
{
	struct mctp_ctrl_msg_hdr hdr = {0};

	mctp_ctrl_msg_hdr_init_req(&hdr, 1, 0x01);
	assert((hdr.rq_dgram_inst & RQDI_IID_MASK) == 1);
	assert(do_type_lookup("control") == 0);
	assert(do_type_lookup("spdm") == 5);
	assert(do_type_lookup("iana") == 0x7f);
	assert(do_type_lookup("definitely-not-a-type") < 0);
}

static void test_find_data_and_create_data(void)
{
	char *argv[] = {"mctp-client", "eid", "8", "type", "control", "data",
			"01", "a0", "FF"};
	struct data_t payload;
	int idx;

	idx = find_data((int)(sizeof(argv) / sizeof(argv[0])), argv);
	assert(idx == 5);

	payload = create_data(&argv[idx + 1], 3);
	assert(payload.len == 3);
	assert(payload.data[0] == 0x01);
	assert(payload.data[1] == 0xa0);
	assert(payload.data[2] == 0xff);
}

static void test_send_recv_and_usage(void)
{
	uint8_t raw[] = {0x01, 0x02};
	struct data_t payload = {
		.data = raw,
		.len = sizeof(raw),
	};

	print_usage();
	assert(do_send_recv(0, 8, 0, &payload) == 0);
	assert(stub_socket_calls > 0);
	assert(stub_sendto_calls > 0);
	assert(stub_recvfrom_calls >= 2);
}

static void test_main_happy_path(void)
{
	char *argv[] = {"mctp-client", "eid", "8", "type", "control", "data",
			"01", "02"};
	int argc = (int)(sizeof(argv) / sizeof(argv[0]));

	assert(mctp_client_main(argc, argv) == 0);
}

static void test_main_missing_params(void)
{
	char *argv1[] = {"mctp-client", "eid", "8", "type", "control"};
	char *argv2[] = {"mctp-client", "type", "control", "data", "01"};
	char *argv3[] = {"mctp-client", "eid", "8", "type", "control", "net", "abc",
			 "data", "01"};
	assert(mctp_client_main((int)(sizeof(argv1) / sizeof(argv1[0])), argv1) != 0);
	assert(mctp_client_main((int)(sizeof(argv2) / sizeof(argv2[0])), argv2) != 0);
	assert(mctp_client_main((int)(sizeof(argv3) / sizeof(argv3[0])), argv3) != 0);
}

static void test_main_with_net(void)
{
	char *argv[] = {"mctp-client", "net", "7", "eid", "8", "type", "control",
			"data", "01", "02"};
	assert(mctp_client_main((int)(sizeof(argv) / sizeof(argv[0])), argv) == 0);
}

static void test_main_parse_invalid_numeric(void)
{
	char *argv[] = {"mctp-client", "eid", "8", "type", "control", "net",
			"x", "data", "01"};
	assert(mctp_client_main((int)(sizeof(argv) / sizeof(argv[0])), argv) != 0);
}

static void test_error_paths(void)
{
	static const enum child_case cases[] = {
		CC_CREATE_EMPTY,      CC_CREATE_INVALID_TOKEN,
		CC_CREATE_TOO_LARGE,  CC_CREATE_ULONG_MAX,
		CC_MAIN_INVALID_TAG,  CC_MAIN_INVALID_EID,
		CC_MAIN_INVALID_TYPE, CC_SOCKET_FAIL,
		CC_SEND_FAIL,	      CC_SEND_PARTIAL,
		CC_RECV_PEEK_FAIL,    CC_RECV_DATA_FAIL,
		CC_RECV_DATA_SHORT,   CC_RECV_ALLOC_FAIL,
		CC_CREATE_ALLOC_FAIL, CC_CTRL_HDR_ASSERT,
		/* CC_MAIN_INVALID_NET_REPARSE succeeds with stubs; not a failure case */
	};
	size_t i;

	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		active_child_case = cases[i];
		assert(run_child_expect_failure(run_active_child_case));
	}
}

int main(void)
{
	test_type_lookup();
	test_find_data_and_create_data();
	test_send_recv_and_usage();
	test_main_happy_path();
	test_main_missing_params();
	test_main_with_net();
	test_main_parse_invalid_numeric();
	test_error_paths();
	return 0;
}
