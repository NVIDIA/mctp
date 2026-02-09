/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Unit tests for mctp-ops.c wrappers.
 */

#include <assert.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>

#include "mctp-ops.c"

static void call_bug_warn(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	mctp_ops.bug_warn(fmt, args);
	va_end(args);
}

int main(void)
{
	struct sockaddr_storage ss = {0};
	socklen_t slen = sizeof(ss);
	char byte = 0;
	int fd;

	mctp_ops_init();

	fd = mctp_ops.mctp.socket();
	if (fd >= 0)
		mctp_ops.mctp.close(fd);

	fd = mctp_ops.nl.socket();
	if (fd >= 0)
		mctp_ops.nl.close(fd);

	assert(mctp_ops.mctp.bind(-1, (struct sockaddr *)&ss, slen) < 0);
	assert(mctp_ops.mctp.setsockopt(-1, SOL_SOCKET, SO_REUSEADDR, &byte,
					sizeof(byte)) < 0);
	assert(mctp_ops.mctp.sendto(-1, &byte, sizeof(byte), 0,
				    (const struct sockaddr *)&ss, slen) < 0);
	assert(mctp_ops.mctp.recvfrom(-1, &byte, sizeof(byte), 0,
				      (struct sockaddr *)&ss, &slen) < 0);
	assert(mctp_ops.mctp.close(-1) < 0);

	call_bug_warn("unit-test warning path %d", 1);

	return 0;
}
