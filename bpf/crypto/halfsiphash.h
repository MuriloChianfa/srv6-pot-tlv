#ifndef __SEG6_HALFSIPHASH64_H
#define __SEG6_HALFSIPHASH64_H

#include <linux/types.h>

/* HalfSipHash parameters */
#define HALFSIPHASH_CROUNDS 2  /* Compression rounds */
#define HALFSIPHASH_FROUNDS 2  /* Finalization rounds */
#define HALFSIPHASH_TAG_LEN 8

/* HalfSipHash IV constants */
#define HALFSIPH_CONST_0 0x736f6d6570736575ULL
#define HALFSIPH_CONST_1 0x646f72616e646f6dULL
#define HALFSIPH_CONST_2 0x6c7967656e657261ULL
#define HALFSIPH_CONST_3 0x7465646279746573ULL

struct __attribute__((aligned(8))) halfsiphash_key {
    __u64 key[2];
};

static __always_inline __u64 load_u64(const __u8 *src)
{
    return (__u64)src[0]       | (__u64)src[1] <<  8  |
           (__u64)src[2] << 16 | (__u64)src[3] << 24  |
           (__u64)src[4] << 32 | (__u64)src[5] << 40  |
           (__u64)src[6] << 48 | (__u64)src[7] << 56;
}

static __always_inline void halfsiphash_init_state(const struct halfsiphash_key *k, __u64 *v0, __u64 *v1, __u64 *v2, __u64 *v3)
{
    *v0 = HALFSIPH_CONST_0 ^ k->key[0];
    *v1 = HALFSIPH_CONST_1 ^ k->key[1];
    *v2 = HALFSIPH_CONST_2 ^ k->key[0];
    *v3 = HALFSIPH_CONST_3 ^ k->key[1];
}

static __always_inline void halfsiphash_round(__u64 *v0, __u64 *v1, __u64 *v2, __u64 *v3)
{
    *v0 += *v1;
    *v1 = (*v1 << 13) | (*v1 >> (64-13));
    *v1 ^= *v0;
    *v0 = (*v0 << 32) | (*v0 >> (64-32));

    *v2 += *v3;
    *v3 = (*v3 << 16) | (*v3 >> (64-16));
    *v3 ^= *v2;

    *v0 += *v3;
    *v3 = (*v3 << 21) | (*v3 >> (64-21));
    *v3 ^= *v0;

    *v2 += *v1;
    *v1 = (*v1 << 17) | (*v1 >> (64-17));
    *v1 ^= *v2;
    *v2 = (*v2 << 32) | (*v2 >> (64-32));
}

static __always_inline void halfsiphash_compression(__u64 *v0, __u64 *v1, __u64 *v2, __u64 *v3, __u64 m)
{
    *v3 ^= m;

#pragma clang loop unroll(full)
    for (__u8 i = 0; i < HALFSIPHASH_CROUNDS; i++)
        halfsiphash_round(v0, v1, v2, v3);

    *v0 ^= m;
}

static __always_inline void halfsiphash_finalization(__u64 *v0, __u64 *v1, __u64 *v2, __u64 *v3)
{
    *v2 ^= 0xff;

#pragma clang loop unroll(full)
    for (__u8 i = 0; i < HALFSIPHASH_FROUNDS; i++)
        halfsiphash_round(v0, v1, v2, v3);
}

/**
 * Computes a HalfSipHash value for fixed-length data (16 bytes)
 * 
 * @param key      Pointer to the key structure
 * @param data     Pointer to input data (16 bytes)
 * @return         64-bit hash value
 */
static __always_inline __u64 halfsiphash(const struct halfsiphash_key *key, const void *data)
{
    __u64 v0, v1, v2, v3;

    const __u8 *bytes = (const __u8 *)data;

    __u64 m0 = load_u64(bytes + 0);
    __u64 m1 = load_u64(bytes + 8);

    halfsiphash_init_state(key, &v0, &v1, &v2, &v3);

    halfsiphash_compression(&v0, &v1, &v2, &v3, m0);
    halfsiphash_compression(&v0, &v1, &v2, &v3, m1);

    halfsiphash_finalization(&v0, &v1, &v2, &v3);

    return v1 ^ v3;
}

#endif /* __SEG6_HALFSIPHASH64_H */