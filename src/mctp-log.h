/* SPDX-License-Identifier: GPL-2.0 */
#ifndef MCTP_LOG_H
#define MCTP_LOG_H

/*
 * Common logging overrides for MCTP daemon components.
 *
 * When compiling for the daemon (MCTP_DAEMON defined), we redirect
 * standard libc logging functions to systemd journal to eliminate
 * stdio buffering latency and ensure accurate timestamps.
 *
 * When compiling for CLI tools, we keep standard behavior (stderr/stdout).
 */

#ifdef MCTP_JOURNAL_LOGGING

#include <systemd/sd-journal.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

/* Helper for vwarnx replacement */
static inline void mctp_vwarnx(const char *fmt, va_list ap)
{
	char buf[4096];
	vsnprintf(buf, sizeof(buf), fmt, ap);
	sd_journal_print(LOG_WARNING, "%s", buf);
}

#undef warn
#define warn(fmt, ...) \
	sd_journal_print(LOG_WARNING, fmt ": %s", ##__VA_ARGS__, strerror(errno))

#undef warnx
#define warnx(fmt, ...) \
	sd_journal_print(LOG_WARNING, fmt, ##__VA_ARGS__)

#undef vwarnx
#define vwarnx(fmt, ap) mctp_vwarnx(fmt, ap)

#undef err
#define err(eval, fmt, ...) do { \
	sd_journal_print(LOG_ERR, fmt ": %s", ##__VA_ARGS__, strerror(errno)); \
	exit(eval); \
} while(0)

#undef errx
#define errx(eval, fmt, ...) do { \
	sd_journal_print(LOG_ERR, fmt, ##__VA_ARGS__); \
	exit(eval); \
} while(0)

/* Redirect fprintf(stderr, ...) to journal. Ignores the 'stream' argument. */
#undef fprintf
#define fprintf(stream, fmt, ...) \
	sd_journal_print(LOG_ERR, fmt, ##__VA_ARGS__)

/* Redirect printf(...) to journal (info level) */
#undef printf
#define printf(fmt, ...) \
	sd_journal_print(LOG_INFO, fmt, ##__VA_ARGS__)

#endif /* MCTP_DAEMON */

#endif /* MCTP_LOG_H */
