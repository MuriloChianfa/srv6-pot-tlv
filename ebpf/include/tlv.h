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
#define BLAKE3_POT_DIGEST_LEN 32 // Byte-size of the PoT digest
#define BLAKE3_POT_TLV_TYPE 4 // Defines a new TLV type

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
    __u64 timestamp; // Random nonce
    __u32 token; // Random nonce
    __u16 reserved;
    __u8 data[BLAKE3_POT_DIGEST_LEN]; // 256-bit BLAKE3 digest
} __attribute__((packed));

static __always_inline void compute_tlv(struct blake3_pot_tlv *tlv, const __u8 key[32])
{
    blake3_keyed_hash((const __u8 *)&tlv->timestamp, sizeof(tlv->timestamp) + sizeof(tlv->token) + sizeof(tlv->reserved) + sizeof(tlv->data), key, tlv->data);
}

static __always_inline int compare_pot_digest(const struct blake3_pot_tlv *x, const struct blake3_pot_tlv *y)
{
    return __builtin_memcmp(x->data, y->data, BLAKE3_POT_DIGEST_LEN);
}

static __always_inline int fill_tlv(struct blake3_pot_tlv *tlv)
{
    tlv->type = BLAKE3_POT_TLV_TYPE;
    tlv->length = BLAKE3_POT_TLV_WR_LEN;
    tlv->timestamp = bpf_ktime_get_ns();
    tlv->token = bpf_get_prandom_u32();
    tlv->reserved = 0;
    __builtin_memset(tlv->data, 0, sizeof(tlv->data));

    if (sizeof(tlv) % HDR_BYTE_SIZE != 0) {
        bpf_printk("[seg6_pot_tlv][*] warning: TLV length %d not multiple of %d for SRH update", sizeof(tlv), HDR_BYTE_SIZE);
        return -1;
    }

    return 0;
}

static __always_inline int dup_tlv_nonce(const struct blake3_pot_tlv *src, struct blake3_pot_tlv *dst)
{
    __builtin_memcpy(dst, src, sizeof(*dst));
    __builtin_memset(dst->data, 0, sizeof(dst->data));

    if (sizeof(dst) % HDR_BYTE_SIZE != 0) {
        bpf_printk("[seg6_pot_tlv][*] warning: TLV length %d not multiple of %d for SRH update", sizeof(dst), HDR_BYTE_SIZE);
        return -1;
    }

    return 0;
}

static __always_inline void dump_pot_digest(const struct blake3_pot_tlv *x, const struct blake3_pot_tlv *y)
{
    bpf_printk("[seg6_pot_tlv][*] PoT digest on the wire");
    bpf_printk("%02x%02x%02x%02x%02x%02x%02x%02x", x->data[ 0], x->data[ 1], x->data[ 2], x->data[ 3], x->data[ 4], x->data[ 5], x->data[ 6], x->data[ 7]);
    bpf_printk("%02x%02x%02x%02x%02x%02x%02x%02x", x->data[ 8], x->data[ 9], x->data[10], x->data[11], x->data[12], x->data[13], x->data[14], x->data[15]);
    bpf_printk("%02x%02x%02x%02x%02x%02x%02x%02x", x->data[16], x->data[17], x->data[18], x->data[19], x->data[20], x->data[21], x->data[22], x->data[23]);
    bpf_printk("%02x%02x%02x%02x%02x%02x%02x%02x", x->data[24], x->data[25], x->data[26], x->data[27], x->data[28], x->data[29], x->data[30], x->data[31]);
    bpf_printk("[seg6_pot_tlv][*] PoT digest recalculated");
    bpf_printk("%02x%02x%02x%02x%02x%02x%02x%02x", y->data[ 0], y->data[ 1], y->data[ 2], y->data[ 3], y->data[ 4], y->data[ 5], y->data[ 6], y->data[ 7]);
    bpf_printk("%02x%02x%02x%02x%02x%02x%02x%02x", y->data[ 8], y->data[ 9], y->data[10], y->data[11], y->data[12], y->data[13], y->data[14], y->data[15]);
    bpf_printk("%02x%02x%02x%02x%02x%02x%02x%02x", y->data[16], y->data[17], y->data[18], y->data[19], y->data[20], y->data[21], y->data[22], y->data[23]);
    bpf_printk("%02x%02x%02x%02x%02x%02x%02x%02x", y->data[24], y->data[25], y->data[26], y->data[27], y->data[28], y->data[29], y->data[30], y->data[31]);
}

#endif /* __BLAKE3_POT_TLV_H */