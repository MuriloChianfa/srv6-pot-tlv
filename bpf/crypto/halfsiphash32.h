#ifndef __SEG6_HALFSIPHASH32_H
#define __SEG6_HALFSIPHASH32_H

#include <linux/types.h>

/* HalfSipHash parameters */
#define HALFSIPHASH_TAG_LEN 4
#define HALFSIPHASH_CROUNDS 2  /* Compression rounds */
#define HALFSIPHASH_FROUNDS 4  /* Finalization rounds */

/* HalfSipHash constants (32-bit variants) */
#define HALFSIPHASH_CONST_0 0x00000000U
#define HALFSIPHASH_CONST_1 0x00000000U
#define HALFSIPHASH_CONST_2 0x6c796765U
#define HALFSIPHASH_CONST_3 0x74656462U

struct __attribute__((aligned(4))) halfsiphash_key {
    __u32 key[2];
};

static __always_inline __u32 load_u32(const __u8 *src)
{
    return ((__u32)src[0]) |
           ((__u32)src[1] << 8) |
           ((__u32)src[2] << 16) |
           ((__u32)src[3] << 24);
}

static __always_inline void halfsiphash_init_state(const struct halfsiphash_key *key, 
                                                 __u32 *v0, __u32 *v1, __u32 *v2, __u32 *v3)
{
    *v0 = HALFSIPHASH_CONST_0 ^ key->key[0];
    *v1 = HALFSIPHASH_CONST_1 ^ key->key[1];
    *v2 = HALFSIPHASH_CONST_2 ^ key->key[0];
    *v3 = HALFSIPHASH_CONST_3 ^ key->key[1];
}

static __always_inline void halfsiphash_round(__u32 *v0, __u32 *v1, __u32 *v2, __u32 *v3)
{
    *v0 += *v1;
    *v1 = (*v1 << 5) | (*v1 >> 27);
    *v1 ^= *v0;
    *v0 = (*v0 << 16) | (*v0 >> 16);
    
    *v2 += *v3;
    *v3 = (*v3 << 8) | (*v3 >> 24);
    *v3 ^= *v2;
    
    *v0 += *v3;
    *v3 = (*v3 << 7) | (*v3 >> 25);
    *v3 ^= *v0;
    
    *v2 += *v1;
    *v1 = (*v1 << 13) | (*v1 >> 19);
    *v1 ^= *v2;
    *v2 = (*v2 << 16) | (*v2 >> 16);
}

static __always_inline void halfsiphash_compression(__u32 *v0, __u32 *v1, __u32 *v2, __u32 *v3, __u32 m)
{
    *v3 ^= m;

#pragma clang loop unroll(full)
    for (__u8 i = 0; i < HALFSIPHASH_CROUNDS; i++)
        halfsiphash_round(v0, v1, v2, v3);

    *v0 ^= m;
}

static __always_inline void halfsiphash_finalization(__u32 *v0, __u32 *v1, __u32 *v2, __u32 *v3)
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
 * @return         32-bit hash value
 */
static __always_inline __u32 halfsiphash32(const struct halfsiphash_key *key, const void *data)
{
    __u32 v0, v1, v2, v3;
    __u32 m0, m1, m2, m3;

    const __u8 *bytes = (const __u8 *)data;

    m0 = load_u32(bytes);
    m1 = load_u32(bytes + 4);
    m2 = load_u32(bytes + 8);
    m3 = load_u32(bytes + 12);

    halfsiphash_init_state(key, &v0, &v1, &v2, &v3);

    halfsiphash_compression(&v0, &v1, &v2, &v3, m0);
    halfsiphash_compression(&v0, &v1, &v2, &v3, m1);
    halfsiphash_compression(&v0, &v1, &v2, &v3, m2);
    halfsiphash_compression(&v0, &v1, &v2, &v3, m3);

    halfsiphash_finalization(&v0, &v1, &v2, &v3);

    return v1 ^ v3;
}

#endif /* __SEG6_HALFSIPHASH32_H */