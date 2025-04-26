#ifndef __SEG6_POT_TLV_H
#define __SEG6_POT_TLV_H

#include <linux/bpf.h>
#include <linux/types.h>

#include <linux/in6.h>
#include <linux/icmpv6.h>

#include "crypto/nonce.h"
#include "crypto/blake3.h"
#include "exp.h"
#include "srh.h"
#include "hdr.h"

/* PoT TLV properties*/
#define POT_TLV_TYPE 0x04u
#define POT_TLV_FLAGS 0x0000u
#define POT_TLV_WIRE_LEN sizeof(struct pot_tlv)
#define POT_TLV_LEN (POT_TLV_WIRE_LEN - 2)
#define POT_TLV_EXT_LEN (POT_TLV_WIRE_LEN / HDR_BYTE_SIZE)

/*
Define the custom TLV structure for proof-of-transit using BLAKE3.
  0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
|   Type (8b)   |  Length (8b)  |      Reserved/Flags (16b)      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
|                          Nonce (96b)                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
|                        Witness (256b)                          |
|                            ...                                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
|                          Root 256b                             |
|                            ...                                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
*/
struct pot_tlv {
    __u8 type;
    __u8 length;
    __u16 reserved;
    __u8 nonce[NONCE_LEN];
    __u8 witness[BLAKE3_DIGEST_LEN];
    __u8 root[BLAKE3_DIGEST_LEN];
} __attribute__((packed));

static __always_inline void compute_tlv(struct pot_tlv *tlv, const __u8 key[32])
{
    blake3_keyed_hash((const __u8 *)&tlv->nonce, sizeof(tlv->nonce) + sizeof(tlv->witness), key, (__u8 *)tlv->witness);
}

static __always_inline int compare_pot_digest(const struct pot_tlv *x, const struct pot_tlv *y)
{
    return __builtin_memcmp(x->witness, y->witness, BLAKE3_DIGEST_LEN)
        && __builtin_memcmp(x->root, y->witness, BLAKE3_DIGEST_LEN);
}

static __always_inline void zerofy_witness(const struct pot_tlv *tlv)
{
    __builtin_memcpy((void *)tlv->root, tlv->witness, sizeof(tlv->root));
    __builtin_memset((void *)tlv->witness, 0, sizeof(tlv->witness));
}

static __always_inline void init_tlv(struct pot_tlv *tlv)
{
    tlv->type= POT_TLV_TYPE;
    tlv->length = POT_TLV_LEN;
    tlv->reserved = POT_TLV_FLAGS;
    new_nonce(tlv->nonce);
    __builtin_memset(tlv->root, 0, sizeof(tlv->root));
    __builtin_memset(tlv->witness, 0, sizeof(tlv->witness));

    if (sizeof(tlv) % HDR_BYTE_SIZE != 0)
        bpf_printk("[seg6_pot_tlv][*] warning: TLV length %d not multiple of %d for SRH update", sizeof(tlv), HDR_BYTE_SIZE);
}

static __always_inline void dup_tlv_nonce(const struct pot_tlv *src, struct pot_tlv *dst)
{
    __builtin_memcpy(dst, src, sizeof(*dst));
    __builtin_memset(dst->witness, 0, sizeof(dst->witness));

    if (sizeof(dst) % HDR_BYTE_SIZE != 0)
        bpf_printk("[seg6_pot_tlv][*] warning: TLV length %d not multiple of %d for SRH update", sizeof(dst), HDR_BYTE_SIZE);
}

static __always_inline void dump_pot_digest(const struct pot_tlv *x, const struct pot_tlv *y)
{
    bpf_printk("[seg6_pot_tlv][*] PoT digest on the wire");
    bpf_printk("%02x%02x%02x%02x%02x%02x%02x%02x", x->witness[ 0], x->witness[ 1], x->witness[ 2], x->witness[ 3], x->witness[ 4], x->witness[ 5], x->witness[ 6], x->witness[ 7]);
    bpf_printk("%02x%02x%02x%02x%02x%02x%02x%02x", x->witness[ 8], x->witness[ 9], x->witness[10], x->witness[11], x->witness[12], x->witness[13], x->witness[14], x->witness[15]);
    bpf_printk("%02x%02x%02x%02x%02x%02x%02x%02x", x->witness[16], x->witness[17], x->witness[18], x->witness[19], x->witness[20], x->witness[21], x->witness[22], x->witness[23]);
    bpf_printk("%02x%02x%02x%02x%02x%02x%02x%02x", x->witness[24], x->witness[25], x->witness[26], x->witness[27], x->witness[28], x->witness[29], x->witness[30], x->witness[31]);
    bpf_printk("[seg6_pot_tlv][*] PoT digest recalculated");
    bpf_printk("%02x%02x%02x%02x%02x%02x%02x%02x", y->witness[ 0], y->witness[ 1], y->witness[ 2], y->witness[ 3], y->witness[ 4], y->witness[ 5], y->witness[ 6], y->witness[ 7]);
    bpf_printk("%02x%02x%02x%02x%02x%02x%02x%02x", y->witness[ 8], y->witness[ 9], y->witness[10], y->witness[11], y->witness[12], y->witness[13], y->witness[14], y->witness[15]);
    bpf_printk("%02x%02x%02x%02x%02x%02x%02x%02x", y->witness[16], y->witness[17], y->witness[18], y->witness[19], y->witness[20], y->witness[21], y->witness[22], y->witness[23]);
    bpf_printk("%02x%02x%02x%02x%02x%02x%02x%02x", y->witness[24], y->witness[25], y->witness[26], y->witness[27], y->witness[28], y->witness[29], y->witness[30], y->witness[31]);
}

#endif /* __SEG6_POT_TLV_H */