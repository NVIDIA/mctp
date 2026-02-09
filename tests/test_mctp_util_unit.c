/* SPDX-License-Identifier: GPL-2.0 */

#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int stub_malloc_fail;
static int stub_snprintf_mode;

static void *test_malloc(size_t size)
{
	if (stub_malloc_fail)
		return NULL;
	return calloc(1, size);
}

static int test_snprintf(char *str, size_t size, const char *fmt, ...)
{
	va_list ap;

	if (stub_snprintf_mode == 1)
		return (int)size;
	if (stub_snprintf_mode == 2 && strcmp(fmt, "%02x") == 0)
		return (int)size;
	if (stub_snprintf_mode == 3 && strcmp(fmt, ":") == 0)
		return (int)size;

	va_start(ap, fmt);
	int rc = vsnprintf(str, size, fmt, ap);
	va_end(ap);
	return rc;
}

#define malloc test_malloc
#define snprintf test_snprintf
#include "mctp-util.c"

static void test_write_hex_addr(void)
{
	uint8_t bytes[] = {0x01, 0xa2, 0xff};
	char out[32];

	assert(write_hex_addr(bytes, 3, out, sizeof(out)) == 0);
	assert(strcmp(out, "01:a2:ff") == 0);
	assert(write_hex_addr(bytes, 3, out, 2) == -EINVAL);
	stub_snprintf_mode = 1;
	assert(write_hex_addr(bytes, 2, out, sizeof(out)) == -EPROTO);
	stub_snprintf_mode = 2;
	assert(write_hex_addr(bytes, 1, out, sizeof(out)) == -EPROTO);
	stub_snprintf_mode = 3;
	assert(write_hex_addr(bytes, 2, out, 6) == -EPROTO);
	stub_snprintf_mode = 0;
}

static void test_parse_hex_addr(void)
{
	uint8_t out[8];
	size_t out_len;

	out_len = sizeof(out);
	assert(parse_hex_addr("", out, &out_len) == 0);
	assert(out_len == 0);

	out_len = sizeof(out);
	assert(parse_hex_addr("01:02:ff", out, &out_len) == 0);
	assert(out_len == 3);
	assert(out[0] == 0x01 && out[1] == 0x02 && out[2] == 0xff);

	out_len = sizeof(out);
	assert(parse_hex_addr(":01", out, &out_len) < 0 && out_len == 0);
	out_len = sizeof(out);
	assert(parse_hex_addr("01::02", out, &out_len) < 0 && out_len == 0);
	out_len = sizeof(out);
	assert(parse_hex_addr("01:", out, &out_len) < 0 && out_len == 0);
	out_len = sizeof(out);
	assert(parse_hex_addr("01:100", out, &out_len) < 0 && out_len == 0);
	out_len = sizeof(out);
	assert(parse_hex_addr("GG", out, &out_len) < 0 && out_len == 0);
	out_len = 1;
	assert(parse_hex_addr("01:02", out, &out_len) < 0 && out_len == 0);
}

static void test_integer_parsers(void)
{
	uint32_t u32 = 0;
	int32_t i32 = 0;
	mctp_eid_t eid = 0;

	assert(parse_uint32("123", &u32) == 0 && u32 == 123);
	assert(parse_uint32("0x123", &u32) == 0 && u32 == 0x123);
	assert(parse_uint32("", &u32) == -EINVAL);
	assert(parse_uint32("12x", &u32) == -EINVAL);
	assert(parse_uint32("4294967296", &u32) == -EOVERFLOW);

	assert(parse_int32("123", &i32) == 0 && i32 == 123);
	assert(parse_int32("-123", &i32) == 0 && i32 == -123);
	assert(parse_int32("", &i32) == -EINVAL);
	assert(parse_int32("12x", &i32) == -EINVAL);
	assert(parse_int32("2147483648", &i32) == -EOVERFLOW);
	assert(parse_int32("-2147483649", &i32) == -EOVERFLOW);

	assert(parse_eid("42", &eid) == 0 && eid == 42);
	assert(parse_eid("255", &eid) == 0 && eid == 255);
	assert(parse_eid("256", &eid) < 0);
	assert(parse_eid("bad", &eid) < 0);
}

static void test_uuid_and_eid(void)
{
	uint8_t uuid[16];
	char *uuid_str;

	for (int i = 0; i < 16; i++)
		uuid[i] = (uint8_t)i;

	uuid_str = bytes_to_uuid(uuid);
	assert(uuid_str != NULL);
	assert(strlen(uuid_str) == 36);
	assert(uuid_str[8] == '-' && uuid_str[13] == '-' &&
	       uuid_str[18] == '-' && uuid_str[23] == '-');
	free(uuid_str);
	stub_malloc_fail = 1;
	assert(bytes_to_uuid(uuid) == NULL);
	stub_malloc_fail = 0;

	assert(mctp_eid_is_valid_unicast(7) == false);
	assert(mctp_eid_is_valid_unicast(8) == true);
	assert(mctp_eid_is_valid_unicast(200) == true);
	assert(mctp_eid_is_valid_unicast(0xff) == false);
}

static void test_hexdump_and_print_hex(void)
{
	/* mctp_hexdump: exercises !isprint(c) branch (L24) */
	uint8_t data[] = { 0x01, 0x41, 0x00, 0xFF, 0x7F, 0x20 };
	mctp_hexdump(data, sizeof(data), "  ");

	/* print_hex_addr: exercises i > 0 branch (L40) */
	uint8_t addr[] = { 0xAA, 0xBB, 0xCC };
	print_hex_addr(addr, sizeof(addr));
	printf("\n");

	/* Single byte — i > 0 never true */
	print_hex_addr(addr, 1);
	printf("\n");

	/* Empty — loop doesn't execute */
	print_hex_addr(addr, 0);
}

int main(void)
{
	test_write_hex_addr();
	test_parse_hex_addr();
	test_integer_parsers();
	test_uuid_and_eid();
	test_hexdump_and_print_hex();
	return 0;
}
