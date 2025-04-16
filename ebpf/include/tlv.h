#ifndef __BLAKE3_POT_TLV_H
#define __BLAKE3_POT_TLV_H

#include <linux/bpf.h>
#include <linux/types.h>

#include <linux/in6.h>
#include <linux/icmpv6.h>

#include "crypto/blake3.h"
#include "exp.h"
#include "srh.h"
#include "hdr.h"

/*
Define the custom TLV structure for proof-of-transit using BLAKE3.
  0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
|   Type (8b)   |  Length (8b)  |      Reserved/Flags (16b)      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
|                          Token (32b)                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
|                        Timestamp (64b)                         |
|                            ...                                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
|                        (BLAKE3 256b)                           |
|                            ...                                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
*/
struct blake3_pot_tlv {
    __u8 type;
    __u8 length;
    __u64 timestamp;
    __u32 token;
    __u16 reserved;
    __u8 data[32]; // 256-bit BLAKE3 digest
} __attribute__((packed));

/*
Total TLV length = 48 bytes.
 Bytes 0: TLV Type (TRANSIT_TLV_TYPE)
 Bytes 1: Payload Length (46 bytes = 14 transit + 32 digest)
 Bytes 2-9: Timestamp (8 bytes)
 Bytes 10-13: Token (4 bytes)
 Bytes 14-15: Reserved (2 bytes)
 Bytes 16-47: BLAKE3 digest (32 bytes)
*/
#define BLAKE3_POT_TLV_LEN sizeof(struct blake3_pot_tlv)
#define BLAKE3_POT_TLV_WR_LEN (BLAKE3_POT_TLV_LEN - 2) // 14 transit + 32 digest
#define BLAKE3_POT_TLV_EXT_LEN (BLAKE3_POT_TLV_LEN / HDR_BYTE_SIZE)
#define BLAKE3_POT_TLV_TYPE 4 // Defines a new TLV type

static __always_inline int fill_tlv(struct blake3_pot_tlv *tlv)
{
    tlv->type = BLAKE3_POT_TLV_TYPE;
    tlv->length = BLAKE3_POT_TLV_WR_LEN;
    tlv->timestamp = bpf_ktime_get_ns();
    tlv->token = bpf_get_prandom_u32();
    tlv->reserved = 0;

    if (sizeof(tlv) % HDR_BYTE_SIZE != 0) {
        bpf_printk("[seg6_pot_tlv] warning: TLV length %d not multiple of %d for SRH update", sizeof(tlv), HDR_BYTE_SIZE);
        return -1;
    }

    return 0;
}

static __always_inline void compute_tlv(struct blake3_pot_tlv *tlv, const __u8 key[32])
{
    blake3_keyed_hash((const __u8 *)&tlv->timestamp, sizeof(tlv->timestamp) + sizeof(tlv->token) + sizeof(tlv->reserved), key, tlv->data);
}

#endif /* __BLAKE3_POT_TLV_H */