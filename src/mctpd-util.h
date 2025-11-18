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
	if (strstr(ifname, "irot"))
		return "VDM";
	if (strstr(ifname, "vrot"))
		return "VDM";
	return "Unknown";
}

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
	MCTP_PHYS_BINDING_UNSPEC	= 0x00,
	MCTP_PHYS_BINDING_SMBUS		= 0x01,
	MCTP_PHYS_BINDING_PCIE_VDM	= 0x02,
	MCTP_PHYS_BINDING_USB		= 0x03,
	MCTP_PHYS_BINDING_KCS		= 0x04,
	MCTP_PHYS_BINDING_SERIAL	= 0x05,
	MCTP_PHYS_BINDING_I3C		= 0x06,
	MCTP_PHYS_BINDING_MMBI		= 0x07,
	MCTP_PHYS_BINDING_PCC		= 0x08,
	MCTP_PHYS_BINDING_UCIE		= 0x09,
	MCTP_PHYS_BINDING_VENDOR	= 0xFF,
};
 
 struct mctp_error {
	 uint32_t error_code;
	 uint8_t direction;
	 uint8_t binding;
	 uint16_t reserved1;      /* Padding for alignment */
	 uint8_t src_eid;
	 uint8_t dest_eid;
	 uint8_t tag;
	 uint8_t msg_type;
	 uint64_t timestamp_ns;
	 uint16_t payload_len;
	 uint16_t reserved2;      /* Padding for alignment */
	 uint8_t payload[MCTP_ERROR_PAYLOAD_SIZE];
 } __attribute__((packed));

#endif
