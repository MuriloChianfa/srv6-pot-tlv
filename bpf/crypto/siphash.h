#ifndef __SEG6_SIPHASH_H
#define __SEG6_SIPHASH_H

#include <linux/types.h>

#define SIPHASH_INJEST_LEN 20
#define SIPHASH_WORD_LEN 8

/* SipHash parameters */
#define SIPHASH_CROUNDS 2  /* Compression rounds */
#define SIPHASH_FROUNDS 4  /* Finalization rounds */

/* SipHash constants */
#define SIPHASH_CONST_0 0x736f6d6570736575ULL
#define SIPHASH_CONST_1 0x646f72616e646f6dULL
#define SIPHASH_CONST_2 0x6c7967656e657261ULL
#define SIPHASH_CONST_3 0x7465646279746573ULL

struct siphash_key {
    __u64 key[4];
};

static __always_inline void siphash_init_state_256(const struct siphash_key *key, __u64 *v0, __u64 *v1, __u64 *v2, __u64 *v3)
{
    *v0 = SIPHASH_CONST_0 ^ key->key[0];
    *v1 = SIPHASH_CONST_1 ^ key->key[1];
    *v2 = SIPHASH_CONST_2 ^ key->key[2];
    *v3 = SIPHASH_CONST_3 ^ key->key[3];
}

static __always_inline void siphash_round(__u64 *v0, __u64 *v1, __u64 *v2, __u64 *v3)
{
    *v0 += *v1;
    *v1 = (*v1 << 13) | (*v1 >> 51);
    *v1 ^= *v0;
    *v0 = (*v0 << 32) | (*v0 >> 32);
    
    *v2 += *v3;
    *v3 = (*v3 << 16) | (*v3 >> 48);
    *v3 ^= *v2;
    
    *v2 += *v1;
    *v1 = (*v1 << 17) | (*v1 >> 47);
    *v1 ^= *v2;
    *v2 = (*v2 << 32) | (*v2 >> 32);
    
    *v0 += *v3;
    *v3 = (*v3 << 21) | (*v3 >> 43);
    *v3 ^= *v0;
}

static __always_inline void siphash_compression(__u64 *v0, __u64 *v1, __u64 *v2, __u64 *v3, __u64 m)
{
    *v3 ^= m;

#pragma clang loop unroll(full)
    for (__u8 i = 0; i < SIPHASH_CROUNDS; i++)
        siphash_round(v0, v1, v2, v3);

    *v0 ^= m;
}

static __always_inline void siphash_finalization(__u64 *v0, __u64 *v1, __u64 *v2, __u64 *v3)
{
    *v2 ^= 0xff;

#pragma clang loop unroll(full)
    for (__u8 i = 0; i < SIPHASH_FROUNDS; i++)
        siphash_round(v0, v1, v2, v3);
}

static __always_inline __u64 load_u64(const __u8 *src)
{
    return ((__u64)src[0]) |
           ((__u64)src[1] << 8) |
           ((__u64)src[2] << 16) |
           ((__u64)src[3] << 24) |
           ((__u64)src[4] << 32) |
           ((__u64)src[5] << 40) |
           ((__u64)src[6] << 48) |
           ((__u64)src[7] << 56);
}

static __always_inline __u64 siphash(const struct siphash_key *key, const void *data)
{
    __u64 v0, v1, v2, v3;
    __u64 m0, m1, m2;

    const __u8 *bytes = (const __u8 *)data;

    m0 = load_u64(bytes);
    m1 = load_u64(bytes + 8);
    m2 = ((__u64)bytes[16]) | ((__u64)bytes[17] << 8) | 
          ((__u64)bytes[18] << 16) | ((__u64)bytes[19] << 24) |
          ((__u64)SIPHASH_INJEST_LEN << 56);

    siphash_init_state_256(key, &v0, &v1, &v2, &v3);

    siphash_compression(&v0, &v1, &v2, &v3, m0);
    siphash_compression(&v0, &v1, &v2, &v3, m1);
    siphash_compression(&v0, &v1, &v2, &v3, m2);

    siphash_finalization(&v0, &v1, &v2, &v3);
    
    return v0 ^ v1 ^ v2 ^ v3;
}

#endif /* __SEG6_SIPHASH_H */