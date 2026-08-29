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

#ifndef _MCTPD_UTIL_H
#define _MCTPD_UTIL_H

#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#ifndef MCTP_OPT_ENABLE_ERRQUEUE
#define MCTP_OPT_ENABLE_ERRQUEUE 2
#endif

#ifndef MCTP_RECVERR
#define MCTP_RECVERR 1
#endif

#ifndef MCTP_ERROR_PAYLOAD_SIZE
#define MCTP_ERROR_PAYLOAD_SIZE 64
#endif

#define MCTP_DIR_TX 0
#define MCTP_DIR_RX 1

/* MCTP Binding Types (must match kernel values in linux/mctp.h) */
enum mctp_phys_binding {
	MCTP_PHYS_BINDING_UNSPEC = 0x00,
	MCTP_PHYS_BINDING_SMBUS = 0x01,
	MCTP_PHYS_BINDING_PCIE_VDM = 0x02,
	MCTP_PHYS_BINDING_USB = 0x03,
	MCTP_PHYS_BINDING_KCS = 0x04,
	MCTP_PHYS_BINDING_SERIAL = 0x05,
	MCTP_PHYS_BINDING_I3C = 0x06,
	MCTP_PHYS_BINDING_MMBI = 0x07,
	MCTP_PHYS_BINDING_PCC = 0x08,
	MCTP_PHYS_BINDING_UCIE = 0x09,
	MCTP_PHYS_BINDING_VENDOR = 0xFF,
};

/* MCTP Physical Media Type Identifiers as per DSP0236 (v1.7.1) - Table 2 */
enum mctp_phys_media_type {
	MCTP_PHYS_MEDIA_UNSPEC = 0x00,
	MCTP_PHYS_MEDIA_SMBUS_100KHZ = 0x01, /* SMBus 2.0 100 kHz compatible */
	MCTP_PHYS_MEDIA_SMBUS_I2C_100KHZ =
		0x02, /* SMBus 2.0 + I2C 100 kHz compatible */
	MCTP_PHYS_MEDIA_I2C_100KHZ = 0x03, /* I2C 100 kHz (Standard-mode) */
	MCTP_PHYS_MEDIA_I2C_400KHZ = 0x04, /* I2C 400 kHz (Fast-mode) */
	MCTP_PHYS_MEDIA_I2C_1MHZ = 0x05, /* I2C 1 MHz (Fast-mode Plus) */
	MCTP_PHYS_MEDIA_I2C_3_4MHZ = 0x06, /* I2C 3.4 MHz (High-speed mode) */
	/* 0x07 Reserved */
	MCTP_PHYS_MEDIA_PCIE_1_1 = 0x08, /* PCIe 1.1 compatible */
	MCTP_PHYS_MEDIA_PCIE_2_0 = 0x09, /* PCIe 2.0 compatible */
	MCTP_PHYS_MEDIA_PCIE_2_1 = 0x0A, /* PCIe 2.1 compatible */
	MCTP_PHYS_MEDIA_PCIE_3_0 = 0x0B, /* PCIe 3.0 compatible */
	/* 0x0C-0x0E Reserved */
	MCTP_PHYS_MEDIA_PCI = 0x0F, /* PCI compatible (1.0-3.0, PCI-X) */
	MCTP_PHYS_MEDIA_USB_1_1 = 0x10, /* USB 1.1 compatible */
	MCTP_PHYS_MEDIA_USB_2_0 = 0x11, /* USB 2.0 compatible */
	MCTP_PHYS_MEDIA_USB_3_0 = 0x12, /* USB 3.0 compatible */
	/* 0x13-0x17 Reserved */
	MCTP_PHYS_MEDIA_NCSI_RBT =
		0x18, /* NC-SI over RBT (RMII based, DSP0222) */
	/* 0x19-0x1F Reserved */
	MCTP_PHYS_MEDIA_KCS_LEGACY =
		0x20, /* KCS / Legacy (Fixed Address Decoding) */
	MCTP_PHYS_MEDIA_KCS_PCI =
		0x21, /* KCS / PCI (Base Class 0xC0 Subclass 0x01) */
	MCTP_PHYS_MEDIA_SERIAL_LEGACY =
		0x22, /* Serial Host / Legacy (Fixed Address) */
	MCTP_PHYS_MEDIA_SERIAL_PCI =
		0x23, /* Serial Host / PCI (Class 0x07 Subclass 0x00) */
	MCTP_PHYS_MEDIA_ASYNC_SERIAL =
		0x24, /* Asynchronous Serial (Between MCs and IMDs) */
	/* 0x25-0x2F Reserved */
	MCTP_PHYS_MEDIA_I3C_BASIC = 0x30, /* I3C Basic compatible */
	/* 0x31-0x3F Reserved */
	MCTP_PHYS_MEDIA_CXL_1_X = 0x40, /* CXL 1.x */
	/* 0x41-0xFF Reserved */
};

struct mctp_error {
	uint32_t error_code;
	uint8_t direction;
	uint8_t binding;
	uint16_t reserved1; /* Padding for alignment */
	uint8_t src_eid;
	uint8_t dest_eid;
	uint8_t tag;
	uint8_t msg_type;
	uint64_t timestamp_ns;
	uint16_t payload_len;
	uint16_t reserved2; /* Padding for alignment */
	uint8_t payload[MCTP_ERROR_PAYLOAD_SIZE];
} __attribute__((packed));

const char *phy_transport_binding_to_string(uint8_t id)
{
	if (id == 0x0) {
		/* It is defined unspecified in DSP0239 but we used for SPI type */
		return "SPI";
	} else if (id == 0x1) {
		/* MCTP over SMbus */
		return "SMBus";
	} else if (id == 0x2) {
		/*  MCTP over PCI */
		return "PCIe";
	} else if (id == 0x3) {
		/* MCTP over USB */
		return "USB";
	} else if (id == 0x04) {
		/* MCTP over KCS */
		return "KCS";
	} else if (id == 0x05) {
		/* MCTP over Serial*/
		return "Serial";
	} else if (id == 0x06) {
		/* MCTP over I3C*/
		return "I3C";
	}
	return "Unknown";
}

/* Helper function to convert binding string to binding ID */
static inline uint8_t get_binding_id_from_string(const char *binding_str)
{
	if (!binding_str)
		return MCTP_PHYS_BINDING_UNSPEC;
	if (strncmp(binding_str, "SMBus", 5) == 0)
		return MCTP_PHYS_BINDING_SMBUS;
	if (strncmp(binding_str, "USB", 3) == 0)
		return MCTP_PHYS_BINDING_USB;
	if (strncmp(binding_str, "I3C", 3) == 0)
		return MCTP_PHYS_BINDING_I3C;
	if (strncmp(binding_str, "SPI", 3) == 0)
		return MCTP_PHYS_BINDING_UNSPEC; /* SPI uses UNSPEC */
	if (strncmp(binding_str, "PCIe", 4) == 0)
		return MCTP_PHYS_BINDING_PCIE_VDM;
	if (strncmp(binding_str, "VDM", 3) == 0)
		return MCTP_PHYS_BINDING_PCIE_VDM;
	if (strncmp(binding_str, "KCS", 3) == 0)
		return MCTP_PHYS_BINDING_KCS;
	if (strncmp(binding_str, "Serial", 6) == 0)
		return MCTP_PHYS_BINDING_SERIAL;
	return MCTP_PHYS_BINDING_UNSPEC;
}

/* Helper function to convert media type string to media type ID
 * Ideally we should read bus speed to identify media identifier, for
 * now keeping it hardcoded.
 */
static inline uint8_t get_media_type_id_from_string(const char *media_type_str)
{
	if (!media_type_str)
		return MCTP_PHYS_MEDIA_UNSPEC;
	if (strncmp(media_type_str, "SMBus", 5) == 0)
		return MCTP_PHYS_MEDIA_I2C_400KHZ;
	if (strncmp(media_type_str, "USB", 3) == 0)
		return MCTP_PHYS_MEDIA_USB_2_0;
	if (strncmp(media_type_str, "SPI", 3) == 0)
		return MCTP_PHYS_MEDIA_UNSPEC;
	if (strncmp(media_type_str, "PCIe", 4) == 0)
		return MCTP_PHYS_MEDIA_PCIE_3_0;
	if (strncmp(media_type_str, "I3C", 3) == 0)
		return MCTP_PHYS_MEDIA_I3C_BASIC;
	return MCTP_PHYS_MEDIA_UNSPEC;
}
/* Helper function to determine binding type from interface name */
const char *get_binding_from_ifname(const char *ifname)
{
	// TODO: Get this from the IFLA attribute instead of the interface name
	if (!ifname)
		return "Unknown";
	if (strstr(ifname, "i2c"))
		return "SMBus";
	if (strstr(ifname, "usb"))
		return "USB";
	if (strstr(ifname, "spi"))
		return "SPI";
	if (strstr(ifname, "pci"))
		return "PCIe";
	if (strstr(ifname, "irot"))
		return "VDM";
	if (strstr(ifname, "vrot"))
		return "VDM";
	if (strstr(ifname, "i3c"))
		return "I3C";
	return "Unknown";
}

/*
 * =============================================================================
 * Port Number Assignment Algorithm
 * =============================================================================
 *
 * Port numbers are 5-bit values (0-31) used in MCTP routing table entry_type.
 *
 * DESIGN:
 *   - Different bus types get different port ranges (no cross-type collision)
 *   - Within a type, hash the bus number to get port
 *   - Log warning if collision detected (same port for different interfaces)
 *
 * PORT ALLOCATION:
 *   Type     Range        Slots   Description
 *   ──────────────────────────────────────────────────────
 *   I2C      0x00-0x07    8       I2C/SMBus interfaces
 *   USB      0x08-0x0D    6       USB interfaces (full path hashed)
 *   SPI      0x0E-0x13    6       SPI interfaces
 *   I3C      0x14-0x19    6       I3C interfaces
 *   Reserved 0x1A-0x1F    6       Future bus types
 */

/* Bus type identifiers */
enum mctp_port_bus_type {
	MCTP_PORT_BUS_I2C = 0,
	MCTP_PORT_BUS_USB = 1,
	MCTP_PORT_BUS_SPI = 2,
	MCTP_PORT_BUS_I3C = 3,
	MCTP_PORT_BUS_RESERVED = 4,
	MCTP_PORT_BUS_UNKNOWN = 255,
};

/* Port range definitions */
#define MCTP_PORT_I2C_BASE 0x00
#define MCTP_PORT_I2C_SLOTS 8 /* 0x00-0x07 */

#define MCTP_PORT_USB_BASE 0x08
#define MCTP_PORT_USB_SLOTS 6 /* 0x08-0x0D */

#define MCTP_PORT_SPI_BASE 0x0E
#define MCTP_PORT_SPI_SLOTS 6 /* 0x0E-0x13 */

#define MCTP_PORT_I3C_BASE 0x14
#define MCTP_PORT_I3C_SLOTS 6 /* 0x14-0x19 */

#define MCTP_PORT_RSVD_BASE 0x1A
#define MCTP_PORT_RSVD_SLOTS 6 /* 0x1A-0x1F */

#define MCTP_PORT_IFNAME_MAX 64

/* Decoded port information for reverse lookup */
struct mctp_port_info {
	enum mctp_port_bus_type bus_type;
	uint8_t slot_index; /* Slot within type range (0-based) */
	const char *bus_name;
};

/* Collision tracking - stores last interface that used each port (for warning) */
static char mctp_port_last_user[32][MCTP_PORT_IFNAME_MAX];

/* Extract numeric value from string, returns -1 if no digits found */
static inline int extract_number(const char *str)
{
	char *endptr;
	long num = strtol(str, &endptr, 10);

	// Return -1 if no digits were found
	if (endptr == str) {
		return -1;
	}

	return (int)num;
}

/*
 * Hash function: value -> port offset within type range
 */
static inline uint8_t hash_to_port(int value, int num_slots)
{
	if (value < 0)
		value = 0;
	return (uint8_t)(((value * 7) + 3) % num_slots);
}

/*
 * Compute port and log collision warning if different interface uses same port
 */
static inline uint8_t compute_port_with_collision_check(const char *ifname,
							uint8_t base,
							int num_slots,
							int hash_value,
							const char *type_name)
{
	uint8_t port = base + hash_to_port(hash_value, num_slots);

	/* Record this interface as port user */
	strncpy(mctp_port_last_user[port], ifname, MCTP_PORT_IFNAME_MAX - 1);
	mctp_port_last_user[port][MCTP_PORT_IFNAME_MAX - 1] = '\0';

	return port;
}

/*
 * Common helper for simple bus number extraction (I2C, SPI, I3C)
 * Parses: "mctp<prefix><num>", "<prefix>-<num>", "<prefix>_<num>", etc.
 */
static inline uint8_t get_simple_port_number(const char *ifname,
					     const char *prefix, uint8_t base,
					     int num_slots,
					     const char *type_name)
{
	const char *num_start = strstr(ifname, prefix);
	int bus = 0;

	if (num_start) {
		num_start += strlen(prefix) - 1; /* skip prefix */
		if (*num_start == '-' || *num_start == '_')
			num_start++;
		bus = extract_number(num_start);
		if (bus < 0)
			bus = 0;
	}

	return compute_port_with_collision_check(ifname, base, num_slots, bus,
						 type_name);
}

/*
 * Get port number for I2C/SMBus interface
 * Parses: "mctpi2c5", "i2c-3", "mctpi2c32", etc.
 */
static inline uint8_t get_i2c_port_number(const char *ifname)
{
	return get_simple_port_number(ifname, "i2c", MCTP_PORT_I2C_BASE,
				      MCTP_PORT_I2C_SLOTS, "I2C");
}

/*
 * Get port number for USB interface
 * USB topology: bus-port1.port2.port3...
 * Parses: "mctpusb1-1.2.3", "musb2_3_4", etc.
 *
 * Uses FULL path hash: XOR of bus and ALL port numbers
 */
static inline uint8_t get_usb_port_number(const char *ifname)
{
	const char *p = strstr(ifname, "usb");
	int combined = 0;

	if (p) {
		p += strlen("usb") - 1; /* skip "usb" */

		/* Extract bus number */
		int num = extract_number(p);
		if (num >= 0) {
			combined ^= num;
			while (*p >= '0' && *p <= '9')
				p++;
		}

		/* Skip dash separator */
		if (*p == '-' || *p == '_')
			p++;

		/* Extract ALL port numbers in the path */
		while (*p) {
			if (*p >= '0' && *p <= '9') {
				num = extract_number(p);
				if (num >= 0)
					combined ^= num;
				while (*p >= '0' && *p <= '9')
					p++;
			} else if (*p == '.') {
				p++;
			} else {
				break;
			}
		}
	}

	return compute_port_with_collision_check(ifname, MCTP_PORT_USB_BASE,
						 MCTP_PORT_USB_SLOTS, combined,
						 "USB");
}

/*
 * Get port number for SPI interface
 * Parses: "mctpspi0", "spi1", "spi15", etc.
 */
static inline uint8_t get_spi_port_number(const char *ifname)
{
	return get_simple_port_number(ifname, "spi", MCTP_PORT_SPI_BASE,
				      MCTP_PORT_SPI_SLOTS, "SPI");
}

/*
 * Get port number for I3C interface
 * Parses: "mctpi3c0", "i3c-1", "i3c2", etc.
 */
static inline uint8_t get_i3c_port_number(const char *ifname)
{
	return get_simple_port_number(ifname, "i3c", MCTP_PORT_I3C_BASE,
				      MCTP_PORT_I3C_SLOTS, "I3C");
}

/*
 * Get port number for reserved/future bus types
 */
static inline uint8_t get_reserved_port_number(const char *ifname)
{
	/* Hash entire interface name for unknown types */
	int hash = 0;
	const char *p = ifname;
	while (*p) {
		hash = hash * 31 + *p;
		p++;
	}

	return compute_port_with_collision_check(ifname, MCTP_PORT_RSVD_BASE,
						 MCTP_PORT_RSVD_SLOTS, hash,
						 "Reserved");
}

/*
 * Main API: Get 5-bit port number from interface name
 *
 * @param ifname: Network interface name (e.g., "mctpi2c5", "mctpusb1-1.2")
 * @return: 5-bit port number (0x00-0x1F)
 *
 * - Different bus types have separate port ranges (no cross-type collision)
 * - Logs warning if two different interfaces map to same port
 */
static inline uint8_t get_port_from_ifname(const char *ifname)
{
	if (!ifname)
		return MCTP_PORT_I2C_BASE;

	/* Check for I2C - must check before i3c due to substring match */
	if (strstr(ifname, "i2c"))
		return get_i2c_port_number(ifname);

	/* Check for I3C */
	if (strstr(ifname, "i3c"))
		return get_i3c_port_number(ifname);

	/* Check for USB */
	if (strstr(ifname, "usb"))
		return get_usb_port_number(ifname);

	/* Check for SPI */
	if (strstr(ifname, "spi"))
		return get_spi_port_number(ifname);

	/* Unknown bus type - use reserved range */
	return get_reserved_port_number(ifname);
}

/*
 * Reverse Decode: Get bus type from port number
 *
 * @param port_num: 5-bit port number (0-31)
 * @return: Decoded port information with bus type and slot index
 */
static inline struct mctp_port_info decode_port_number(uint8_t port_num)
{
	struct mctp_port_info info = { .bus_type = MCTP_PORT_BUS_UNKNOWN,
				       .slot_index = 0,
				       .bus_name = "Unknown" };

	if (port_num < MCTP_PORT_USB_BASE) {
		info.bus_type = MCTP_PORT_BUS_I2C;
		info.slot_index = port_num - MCTP_PORT_I2C_BASE;
		info.bus_name = "I2C";
	} else if (port_num < MCTP_PORT_SPI_BASE) {
		info.bus_type = MCTP_PORT_BUS_USB;
		info.slot_index = port_num - MCTP_PORT_USB_BASE;
		info.bus_name = "USB";
	} else if (port_num < MCTP_PORT_I3C_BASE) {
		info.bus_type = MCTP_PORT_BUS_SPI;
		info.slot_index = port_num - MCTP_PORT_SPI_BASE;
		info.bus_name = "SPI";
	} else if (port_num < MCTP_PORT_RSVD_BASE) {
		info.bus_type = MCTP_PORT_BUS_I3C;
		info.slot_index = port_num - MCTP_PORT_I3C_BASE;
		info.bus_name = "I3C";
	} else {
		info.bus_type = MCTP_PORT_BUS_RESERVED;
		info.slot_index = port_num - MCTP_PORT_RSVD_BASE;
		info.bus_name = "Reserved";
	}

	return info;
}

/*
 * Helper: Convert port number to human-readable string
 * Returns static buffer - not thread safe, use for logging only
 *
 * Example: port_to_string(0x05) -> "I2C:5"
 *          port_to_string(0x0A) -> "USB:2"
 *          port_to_string(0x15) -> "I3C:1"
 */
static inline const char *port_to_string(uint8_t port_num)
{
	static char buf[32];
	struct mctp_port_info info = decode_port_number(port_num);

	snprintf(buf, sizeof(buf), "%s:%d", info.bus_name, info.slot_index);
	return buf;
}

#endif
