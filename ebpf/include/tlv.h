#ifndef __SEG6_POT_TLV_H
#define __SEG6_POT_TLV_H

#include <linux/bpf.h>
#include <linux/types.h>
#include <linux/in6.h>

#include "crypto/nonce.h"
#include "crypto/blake3.h"
#include "exp.h"
#include "srh.h"
#include "hdr.h"

/* PoT TLV properties*/
#define POT_TLV_TYPE 0x00
#define POT_TLV_FLAGS 0x0000
#define POT_TLV_WIRE_LEN sizeof(struct pot_tlv)
#define POT_TLV_LEN (NONCE_LEN + (BLAKE3_DIGEST_LEN * 2))
#define POT_TLV_EXT_LEN (POT_TLV_WIRE_LEN / HDR_BYTE_SIZE)

/*
Define the custom TLV structure for proof-of-transit using Merkle Tree.
  0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
|   Type (8b)   |  Length (8b)  |      Reserved/Flags (16b)      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
|                         Nonce (96b)                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
|                         Root (256b)                            |
|                            ...                                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
|                       (Witness 256b)                           |
|                            ...                                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
*/
struct pot_tlv {
    __u8  type;
    __u8  length;
    __u16 reserved;
    __u8  nonce[NONCE_LEN];
    __u8  root[BLAKE3_DIGEST_LEN];
    __u8  witness[BLAKE3_DIGEST_LEN];
} __attribute__((packed));

// static __always_inline void compute_tlv(struct pot_tlv *tlv, const __u8 key[32])
// {
//     blake3_keyed_hash((const __u8 *)&tlv->timestamp, sizeof(tlv->timestamp) + sizeof(tlv->token) + sizeof(tlv->reserved) + sizeof(tlv->data), key, tlv->data);
// }

static __always_inline int compare_pot_digest(const struct pot_tlv *x, const struct pot_tlv *y)
{
    return __builtin_memcmp(x->root, y->root, BLAKE3_DIGEST_LEN);
}

static __always_inline void new_empty_tlv(struct pot_tlv *tlv)
{
    tlv->type= POT_TLV_TYPE;
    tlv->length = POT_TLV_WIRE_LEN;
    tlv->reserved = POT_TLV_FLAGS;

    new_nonce((__u8 *)&tlv->nonce);
    __builtin_memset(tlv->root, 0, sizeof(tlv->root));
    __builtin_memset(tlv->witness, 0, sizeof(tlv->witness));

    if (sizeof(tlv) % HDR_BYTE_SIZE != 0)
        bpf_printk("[seg6_pot_tlv][*] warning: TLV length %d not multiple of %d for SRH", sizeof(tlv), HDR_BYTE_SIZE);
}

// static __always_inline void dump_pot_digest(const struct pot_tlv *x, const struct pot_tlv *y)
static __always_inline void dump_tlv_nonce(__u8 leaves[SRH_MAX_ALLOWED_SEGMENTS][BLAKE3_DIGEST_LEN])
{
    // bpf_printk("[seg6_pot_tlv][*] PoT digest on the wire");
    bpf_printk("[seg6_pot_tlv][*] PoT Nonce generated");
    bpf_printk("%02x%02x%02x%02x%02x%02x%02x%02x", leaves[0][ 0], leaves[0][ 1], leaves[0][ 2], leaves[0][ 3], leaves[0][ 4], leaves[0][ 5], leaves[0][ 6], leaves[0][ 7]);
    bpf_printk("%02x%02x%02x%02x%02x%02x%02x%02x", leaves[0][ 8], leaves[0][ 9], leaves[0][10], leaves[0][11], leaves[0][12], leaves[0][13], leaves[0][14], leaves[0][15]);
    bpf_printk("%02x%02x%02x%02x%02x%02x%02x%02x", leaves[0][16], leaves[0][17], leaves[0][18], leaves[0][19], leaves[0][20], leaves[0][21], leaves[0][22], leaves[0][23]);
    bpf_printk("%02x%02x%02x%02x%02x%02x%02x%02x", leaves[0][24], leaves[0][25], leaves[0][26], leaves[0][27], leaves[0][28], leaves[0][29], leaves[0][30], leaves[0][31]);
    // bpf_printk("[seg6_pot_tlv][*] PoT digest recalculated");
    // bpf_printk("%02x%02x%02x%02x%02x%02x%02x%02x", y->data[ 0], y->data[ 1], y->data[ 2], y->data[ 3], y->data[ 4], y->data[ 5], y->data[ 6], y->data[ 7]);
    // bpf_printk("%02x%02x%02x%02x%02x%02x%02x%02x", y->data[ 8], y->data[ 9], y->data[10], y->data[11], y->data[12], y->data[13], y->data[14], y->data[15]);
    // bpf_printk("%02x%02x%02x%02x%02x%02x%02x%02x", y->data[16], y->data[17], y->data[18], y->data[19], y->data[20], y->data[21], y->data[22], y->data[23]);
    // bpf_printk("%02x%02x%02x%02x%02x%02x%02x%02x", y->data[24], y->data[25], y->data[26], y->data[27], y->data[28], y->data[29], y->data[30], y->data[31]);
}

#endif /* __SEG6_POT_TLV_H */