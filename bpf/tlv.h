#ifndef __SEG6_POT_TLV_H
#define __SEG6_POT_TLV_H

#include <linux/bpf.h>
#include <linux/types.h>

#include <linux/in6.h>
#include <linux/icmpv6.h>

#include "crypto/nonce.h"
#include "exp.h"
#include "srh.h"
#include "hdr.h"

/* PoT TLV properties*/
#define POT_TLV_TYPE 0x04u
#define POT_TLV_FLAGS 0x0000u
#define POT_TLV_WIRE_LEN sizeof(struct pot_tlv)
#define POT_TLV_LEN (POT_TLV_WIRE_LEN - 2)
#define POT_TLV_EXT_LEN (POT_TLV_WIRE_LEN / HDR_BYTE_SIZE)

#if POLY1305
    #include "crypto/poly1305.h"
    #define DIGEST_LEN POLY1305_TAG_LEN
#elif HMAC_SHA256
    #include "crypto/hmac-sha256.h"
    #define DIGEST_LEN HMAC_SHA256_DIGEST_LEN
#elif SIPHASH
    #include "crypto/siphash.h"
    #define DIGEST_LEN SIPHASH_WORD_LEN
#elif HALFSIPHASH
    #include "crypto/halfsiphash32.h"
    #define DIGEST_LEN HALFSIPHASH_TAG_LEN
#else
    #include "crypto/blake3.h"
    #define DIGEST_LEN BLAKE3_DIGEST_LEN
#endif

/*
Define the custom TLV structure for proof-of-transit using BLAKE3.
  0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
|   Type (8b)   |  Length (8b)  |      Reserved/Flags (16b)      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
|                          Nonce (96b)                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
|                       Witness (32-256b)                        |
|                            ...                                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
|                        Root (32-256b)                          |
|                            ...                                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
*/
struct pot_tlv {
    __u8 type;
    __u8 length;
    __u16 reserved;
    __u8 nonce[NONCE_LEN];
    __u8 witness[DIGEST_LEN];
    __u8 root[DIGEST_LEN];
} __attribute__((packed));

static __always_inline void compute_tlv(struct pot_tlv *tlv, const __u8 key[32])
{
#if POLY1305
    poly1305((__u8 *)tlv->witness, (const __u8 *)&tlv->nonce, sizeof(tlv->nonce) + sizeof(tlv->witness), key);
#elif HMAC_SHA256
    hmac_sha256(key, 32, (const __u8 *)&tlv->nonce, sizeof(tlv->nonce) + sizeof(tlv->witness), (__u8 *)tlv->witness);
#elif SIPHASH
    struct siphash_key skey;
    __builtin_memcpy(&skey, key, sizeof(struct siphash_key));
    __u64 hash_result = siphash(&skey, (const void *)&tlv->nonce);
    __builtin_memcpy(tlv->witness, &hash_result, DIGEST_LEN);
#elif HALFSIPHASH
    struct halfsiphash_key skey;
    __builtin_memcpy(&skey, key, sizeof(struct halfsiphash_key));
    __u32 hash_result = halfsiphash32(&skey, (const void *)&tlv->nonce);
    __builtin_memcpy(tlv->witness, &hash_result, DIGEST_LEN);
#else
    blake3_keyed_hash((const __u8 *)&tlv->nonce, sizeof(tlv->nonce) + sizeof(tlv->witness), key, (__u8 *)tlv->witness);
#endif
}

static __always_inline int compare_pot_digest(const struct pot_tlv *x, const struct pot_tlv *y)
{
    if (__builtin_memcmp(x->witness, y->witness, DIGEST_LEN) == 0 && __builtin_memcmp(x->root, y->witness, DIGEST_LEN) == 0)
        return 0;
    return -1;
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

#endif /* __SEG6_POT_TLV_H */