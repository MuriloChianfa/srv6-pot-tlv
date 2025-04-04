#ifndef __SEG6_POT_TLV_H__
#define __SEG6_POT_TLV_H__

/* eBPF includes */
#include <linux/bpf.h>
#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ipv6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#define SRH_NEXT_HEADER 43 // SRH next header value per RFC 8754
#define TRANSIT_TLV_TYPE 0xFE // Type for the transit proof TLV

/*
Total TLV length = 48 bytes.
 Bytes 0: TLV Type (TRANSIT_TLV_TYPE)
 Byte  1: Payload Length (46 bytes = 14 transit + 32 digest)
 Bytes 2-9: Timestamp (8 bytes)
 Bytes 10-13: Token (4 bytes)
 Bytes 14-15: Reserved (2 bytes)
 Bytes 16-47: BLAKE3 digest (32 bytes)
*/
#define TRANSIT_TLV_PAYLOAD_LEN 46
#define TRANSIT_TLV_TOTAL_LEN (2 + TRANSIT_TLV_PAYLOAD_LEN)

/*
Define the custom TLV structure for proof-of-transit using BLAKE3.
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-----------------------------------------------------------------+
|      Type      |    Length     |      Reserved/Flags (16 bits)  |
+-----------------------------------------------------------------+
|                         (BLAKE3 Hashs)                          |
+-----------------------------------------------------------------+
*/
struct blake3_pot_tlv {
    __u8 type;     // TLV type identifier
    __u8 length;   // Length of the TLV data
    __u8 data[32]; // 256-bit BLAKE3 digest
};

/* The struct ipv6_sr_hdr is defined in <linux/ipv6.h> */
struct ipv6_sr_hdr {
    __u8  nexthdr;
    __u8  hdrlen;
    __u8  type;
    __u8  segments_left;
    __u8  first_segment;
    __u8  flags;
    __u16 tag;
    struct in6_addr segments[0]; // Variable Lenght
};

#endif /* __SEG6_POT_TLV_H__ */