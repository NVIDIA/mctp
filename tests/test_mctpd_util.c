/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Unit test for mctpd-util.h functions.
 * Exercises all branches in phy_transport_binding_to_string() and
 * get_binding_from_ifname() to improve branch coverage.
 */

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <stdbool.h>

#include "mctpd-util.h"

static int failures = 0;

#define CHECK_STR(func_call, expected) do { \
    const char *_got = (func_call); \
    if (strcmp(_got, (expected)) != 0) { \
        fprintf(stderr, "FAIL: %s returned \"%s\", expected \"%s\"\n", \
                #func_call, _got, expected); \
        failures++; \
    } else { \
        fprintf(stderr, "OK: %s == \"%s\"\n", #func_call, _got); \
    } \
} while (0)

static void check_true(const char *name, bool cond)
{
    if (!cond) {
        fprintf(stderr, "FAIL: %s\n", name);
        failures++;
    } else {
        fprintf(stderr, "OK: %s\n", name);
    }
}

static void check_u8(const char *name, uint8_t got, uint8_t expected)
{
    if (got != expected) {
        fprintf(stderr, "FAIL: %s got=0x%02x expected=0x%02x\n",
                name, got, expected);
        failures++;
    } else {
        fprintf(stderr, "OK: %s == 0x%02x\n", name, got);
    }
}

static void check_i32(const char *name, int got, int expected)
{
    if (got != expected) {
        fprintf(stderr, "FAIL: %s got=%d expected=%d\n", name, got, expected);
        failures++;
    } else {
        fprintf(stderr, "OK: %s == %d\n", name, got);
    }
}

static void test_phy_transport_binding_to_string(void)
{
    fprintf(stderr, "=== test_phy_transport_binding_to_string ===\n");

    /* Every branch: ids 0x0 through 0x06 + unknown */
    CHECK_STR(phy_transport_binding_to_string(0x00), "SPI");
    CHECK_STR(phy_transport_binding_to_string(0x01), "SMBus");
    CHECK_STR(phy_transport_binding_to_string(0x02), "PCIe");
    CHECK_STR(phy_transport_binding_to_string(0x03), "USB");
    CHECK_STR(phy_transport_binding_to_string(0x04), "KCS");
    CHECK_STR(phy_transport_binding_to_string(0x05), "Serial");
    CHECK_STR(phy_transport_binding_to_string(0x06), "I3C");
    /* Unknown / default branch */
    CHECK_STR(phy_transport_binding_to_string(0x07), "Unknown");
    CHECK_STR(phy_transport_binding_to_string(0xFF), "Unknown");
}

static void test_get_binding_from_ifname(void)
{
    fprintf(stderr, "=== test_get_binding_from_ifname ===\n");

    /* NULL branch */
    CHECK_STR(get_binding_from_ifname(NULL), "Unknown");
    /* i2c branch */
    CHECK_STR(get_binding_from_ifname("mctpi2c0"), "SMBus");
    /* usb branch */
    CHECK_STR(get_binding_from_ifname("mctpusb0"), "USB");
    /* spi branch */
    CHECK_STR(get_binding_from_ifname("mctpspi0"), "SPI");
    /* pcie branch */
    CHECK_STR(get_binding_from_ifname("mctppcie0"), "PCIe");
    /* irot branch */
    CHECK_STR(get_binding_from_ifname("mctpirot0"), "VDM");
    /* vrot branch */
    CHECK_STR(get_binding_from_ifname("mctpvrot0"), "VDM");
    /* i3c branch */
    CHECK_STR(get_binding_from_ifname("mctpi3c0"), "I3C");
    /* default / unknown branch */
    CHECK_STR(get_binding_from_ifname("mctpfoo0"), "Unknown");
    CHECK_STR(get_binding_from_ifname("eth0"), "Unknown");
}

static void test_binding_and_media_ids(void)
{
    fprintf(stderr, "=== test_binding_and_media_ids ===\n");
    check_u8("binding NULL", get_binding_id_from_string(NULL), MCTP_PHYS_BINDING_UNSPEC);
    check_u8("binding SMBus", get_binding_id_from_string("SMBus"), MCTP_PHYS_BINDING_SMBUS);
    check_u8("binding USB", get_binding_id_from_string("USB"), MCTP_PHYS_BINDING_USB);
    check_u8("binding I3C", get_binding_id_from_string("I3C"), MCTP_PHYS_BINDING_I3C);
    check_u8("binding SPI", get_binding_id_from_string("SPI"), MCTP_PHYS_BINDING_UNSPEC);
    check_u8("binding PCIe", get_binding_id_from_string("PCIe"), MCTP_PHYS_BINDING_PCIE_VDM);
    check_u8("binding VDM", get_binding_id_from_string("VDM"), MCTP_PHYS_BINDING_PCIE_VDM);
    check_u8("binding KCS", get_binding_id_from_string("KCS"), MCTP_PHYS_BINDING_KCS);
    check_u8("binding Serial", get_binding_id_from_string("Serial"), MCTP_PHYS_BINDING_SERIAL);
    check_u8("binding unknown", get_binding_id_from_string("zzz"), MCTP_PHYS_BINDING_UNSPEC);

    check_u8("media NULL", get_media_type_id_from_string(NULL), MCTP_PHYS_MEDIA_UNSPEC);
    check_u8("media SMBus", get_media_type_id_from_string("SMBus"), MCTP_PHYS_MEDIA_I2C_400KHZ);
    check_u8("media USB", get_media_type_id_from_string("USB"), MCTP_PHYS_MEDIA_USB_2_0);
    check_u8("media SPI", get_media_type_id_from_string("SPI"), MCTP_PHYS_MEDIA_UNSPEC);
    check_u8("media PCIe", get_media_type_id_from_string("PCIe"), MCTP_PHYS_MEDIA_PCIE_3_0);
    check_u8("media I3C", get_media_type_id_from_string("I3C"), MCTP_PHYS_MEDIA_I3C_BASIC);
    check_u8("media unknown", get_media_type_id_from_string("zzz"), MCTP_PHYS_MEDIA_UNSPEC);
}

static void test_port_helpers(void)
{
    fprintf(stderr, "=== test_port_helpers ===\n");
    check_i32("extract_number plain", extract_number("42"), 42);
    check_i32("extract_number suffix", extract_number("12abc"), 12);
    check_i32("extract_number none", extract_number("abc"), -1);
    check_i32("extract_number empty", extract_number(""), -1);
    check_u8("hash negative", hash_to_port(-1, 6), 3);

    check_u8("port null", get_port_from_ifname(NULL), MCTP_PORT_I2C_BASE);
    check_true("port i2c range", get_port_from_ifname("mctpi2c5") < MCTP_PORT_USB_BASE);
    check_true("port i3c range", get_port_from_ifname("mctpi3c1") >= MCTP_PORT_I3C_BASE &&
                                      get_port_from_ifname("mctpi3c1") < MCTP_PORT_RSVD_BASE);
    check_true("port usb range", get_port_from_ifname("mctpusb1-1.2") >= MCTP_PORT_USB_BASE &&
                                      get_port_from_ifname("mctpusb1-1.2") < MCTP_PORT_SPI_BASE);
    check_true("port spi range", get_port_from_ifname("mctpspi3") >= MCTP_PORT_SPI_BASE &&
                                      get_port_from_ifname("mctpspi3") < MCTP_PORT_I3C_BASE);
    check_true("port reserved range", get_port_from_ifname("mctpfoo0") >= MCTP_PORT_RSVD_BASE);

    {
        struct mctp_port_info info;
        info = decode_port_number(0x00);
        check_true("decode i2c", info.bus_type == MCTP_PORT_BUS_I2C && strcmp(info.bus_name, "I2C") == 0);
        info = decode_port_number(0x08);
        check_true("decode usb", info.bus_type == MCTP_PORT_BUS_USB && strcmp(info.bus_name, "USB") == 0);
        info = decode_port_number(0x0E);
        check_true("decode spi", info.bus_type == MCTP_PORT_BUS_SPI && strcmp(info.bus_name, "SPI") == 0);
        info = decode_port_number(0x14);
        check_true("decode i3c", info.bus_type == MCTP_PORT_BUS_I3C && strcmp(info.bus_name, "I3C") == 0);
        info = decode_port_number(0x1A);
        check_true("decode reserved", info.bus_type == MCTP_PORT_BUS_RESERVED &&
                                         strcmp(info.bus_name, "Reserved") == 0);
    }

    check_true("port string format", strstr(port_to_string(0x0A), ":") != NULL);
}

static void test_port_parser_edges(void)
{
    uint8_t p;

    fprintf(stderr, "=== test_port_parser_edges ===\n");

    p = get_simple_port_number("mctpi2c9", "i2c", MCTP_PORT_I2C_BASE, MCTP_PORT_I2C_SLOTS, "I2C");
    check_true("simple parser base path", p < MCTP_PORT_USB_BASE);
    p = get_simple_port_number("mctpi2c4", "i2c", MCTP_PORT_I2C_BASE, MCTP_PORT_I2C_SLOTS, "I2C");
    check_true("simple parser no separator", p < MCTP_PORT_USB_BASE);
    p = get_simple_port_number("mctpi2c_4", "i2c", MCTP_PORT_I2C_BASE, MCTP_PORT_I2C_SLOTS, "I2C");
    check_true("simple parser underscore", p < MCTP_PORT_USB_BASE);
    p = get_simple_port_number("mctpi2c-x", "i2c", MCTP_PORT_I2C_BASE, MCTP_PORT_I2C_SLOTS, "I2C");
    check_true("simple parser invalid number", p < MCTP_PORT_USB_BASE);
    p = get_simple_port_number("mctpfoo", "i2c", MCTP_PORT_I2C_BASE, MCTP_PORT_I2C_SLOTS, "I2C");
    check_true("simple parser missing prefix", p < MCTP_PORT_USB_BASE);

    p = get_usb_port_number("mctpusb1-1.2.3");
    check_true("usb parser dotted path", p >= MCTP_PORT_USB_BASE && p < MCTP_PORT_SPI_BASE);
    p = get_usb_port_number("mctpusb1_2.3");
    check_true("usb parser underscore separator", p >= MCTP_PORT_USB_BASE && p < MCTP_PORT_SPI_BASE);
    p = get_usb_port_number("mctpusb");
    check_true("usb parser no numbers", p >= MCTP_PORT_USB_BASE && p < MCTP_PORT_SPI_BASE);
    p = get_usb_port_number("mctpusb2-2x");
    check_true("usb parser break on suffix", p >= MCTP_PORT_USB_BASE && p < MCTP_PORT_SPI_BASE);
    p = get_usb_port_number("mctpusbx-1");
    check_true("usb parser invalid bus digits", p >= MCTP_PORT_USB_BASE && p < MCTP_PORT_SPI_BASE);
    p = get_usb_port_number("mctpusb12.3");
    check_true("usb parser no explicit separator", p >= MCTP_PORT_USB_BASE && p < MCTP_PORT_SPI_BASE);
    p = get_usb_port_number("mctpusb9-.2");
    check_true("usb parser non-digit path token", p >= MCTP_PORT_USB_BASE && p < MCTP_PORT_SPI_BASE);
    p = get_usb_port_number("mctpfoo");
    check_true("usb parser no usb token", p >= MCTP_PORT_USB_BASE && p < MCTP_PORT_SPI_BASE);
    p = get_usb_port_number("mctpusb1-2a.3");
    check_true("usb parser alpha token in path", p >= MCTP_PORT_USB_BASE && p < MCTP_PORT_SPI_BASE);
    p = get_usb_port_number("mctpusb1/2");
    check_true("usb parser slash separator", p >= MCTP_PORT_USB_BASE && p < MCTP_PORT_SPI_BASE);
    p = get_usb_port_number("mctpusb1-");
    check_true("usb parser trailing dash", p >= MCTP_PORT_USB_BASE && p < MCTP_PORT_SPI_BASE);
    p = get_usb_port_number("usb3-4.5.6");
    check_true("usb parser plain usb token", p >= MCTP_PORT_USB_BASE && p < MCTP_PORT_SPI_BASE);
    p = get_usb_port_number("xusb9_8.7");
    check_true("usb parser embedded token", p >= MCTP_PORT_USB_BASE && p < MCTP_PORT_SPI_BASE);
    p = get_usb_port_number("mctpusb0-0.0");
    check_true("usb parser zero tokens", p >= MCTP_PORT_USB_BASE && p < MCTP_PORT_SPI_BASE);
    p = get_usb_port_number("mctpusb999-1.2.3");
    check_true("usb parser large bus digits", p >= MCTP_PORT_USB_BASE && p < MCTP_PORT_SPI_BASE);
    p = get_usb_port_number("mctpusb3-4_5");
    check_true("usb parser mixed separators", p >= MCTP_PORT_USB_BASE && p < MCTP_PORT_SPI_BASE);
    p = get_usb_port_number("mctpusb-1");
    check_true("usb parser missing bus digits with dash", p >= MCTP_PORT_USB_BASE && p < MCTP_PORT_SPI_BASE);
    p = get_usb_port_number("mctpusb_1");
    check_true("usb parser missing bus digits with underscore", p >= MCTP_PORT_USB_BASE && p < MCTP_PORT_SPI_BASE);
    p = get_usb_port_number("mctpusb1");
    check_true("usb parser bus only", p >= MCTP_PORT_USB_BASE && p < MCTP_PORT_SPI_BASE);
    p = get_usb_port_number("mctpusb1-2.3.4.5");
    check_true("usb parser long dotted path", p >= MCTP_PORT_USB_BASE && p < MCTP_PORT_SPI_BASE);

    p = get_simple_port_number("mctpi2c-4", "i2c", MCTP_PORT_I2C_BASE, MCTP_PORT_I2C_SLOTS, "I2C");
    check_true("simple parser dash separator", p < MCTP_PORT_USB_BASE);
    p = get_simple_port_number("mctpi2cabc", "i2c", MCTP_PORT_I2C_BASE, MCTP_PORT_I2C_SLOTS, "I2C");
    check_true("simple parser alpha suffix", p < MCTP_PORT_USB_BASE);
}

int main(void)
{
    test_phy_transport_binding_to_string();
    test_get_binding_from_ifname();
    test_binding_and_media_ids();
    test_port_helpers();
    test_port_parser_edges();

    if (failures > 0) {
        fprintf(stderr, "\n%d test(s) FAILED\n", failures);
        return 1;
    }
    fprintf(stderr, "\nAll tests passed\n");
    return 0;
}
