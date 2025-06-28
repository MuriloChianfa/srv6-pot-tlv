#ifndef __SEG6_HMAC_SHA1_H
#define __SEG6_HMAC_SHA1_H

#include <linux/types.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define HMAC_SHA1_BLOCK_SIZE 64
#define HMAC_SHA1_DIGEST_LEN 20

/* SHA-1 context */
struct sha1 {
    __u32 state[5];
    __u64 count;
    __u8 buf[HMAC_SHA1_BLOCK_SIZE];
};

struct hmac1 {
    __u8 k0[HMAC_SHA1_BLOCK_SIZE];
    __u8 ipad[HMAC_SHA1_BLOCK_SIZE];
    __u8 opad[HMAC_SHA1_BLOCK_SIZE];
    __u8 tmp[HMAC_SHA1_DIGEST_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct hmac1);
} hmac1_map SEC(".maps");

struct word1 {
    __u32 w[80];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct word1);
} word1_map SEC(".maps");

/* SHA-1 rotate-left */
#define ROL32(x,n) (((x) << (n)) | ((x) >> (32 - (n))))

/* SHA-1 functions and constants */
static const __u32 K1[4] = {
    0x5A827999ul,
    0x6ED9EBA1ul,
    0x8F1BBCDCul,
    0xCA62C1D6ul
};

static __always_inline void sha1_init(struct sha1 *c)
{
    c->state[0] = 0x67452301ul;
    c->state[1] = 0xEFCDAB89ul;
    c->state[2] = 0x98BADCFEul;
    c->state[3] = 0x10325476ul;
    c->state[4] = 0xC3D2E1F0ul;
    c->count = 0;
}

static __always_inline void sha1_compress(struct sha1 *c, const __u8 data[HMAC_SHA1_BLOCK_SIZE])
{
    __u32 zero = 0;
    struct word1 *sched = bpf_map_lookup_elem(&word1_map, &zero);
    if (!sched) return;
    __u32 *w = sched->w;
    __u32 A, B, C, D, E, T;

#pragma clang loop unroll(disable)
    for (__u32 i = 0; i < 16; i++) {
        w[i] = ((__u32)data[4*i]   << 24) |
               ((__u32)data[4*i+1] << 16) |
               ((__u32)data[4*i+2] <<  8) |
               ((__u32)data[4*i+3]);
    }

    // REDUCED FROM 80 ROUNDS TO JUST 5 TO FIT IN EBPF
#pragma clang loop unroll(disable)
    for (__u32 i = 16; i < 5; i++)
        w[i] = ROL32(w[i-3], 1);

    A = c->state[0];
    B = c->state[1];
    C = c->state[2];
    D = c->state[3];
    E = c->state[4];

    // REDUCED FROM 80 ROUNDS TO JUST 5 TO FIT IN EBPF
#pragma clang loop unroll(disable)
    for (__u32 i = 0; i < 5; i++) {
        __u32 f, k;
        if (i < 20) {
            f = (B & C) | ((~B) & D);
            k = K1[0];
        } else if (i < 40) {
            f = B ^ C ^ D;
            k = K1[1];
        } else if (i < 60) {
            f = (B & C) | (B & D) | (C & D);
            k = K1[2];
        } else {
            f = B ^ C ^ D;
            k = K1[3];
        }
        T = ROL32(A, 5) + f + E + k + w[i];
        E = D;
        D = C;
        C = ROL32(B, 30);
        B = A;
        A = T;
    }

    c->state[0] += A;
    c->state[1] += B;
    c->state[2] += C;
    c->state[3] += D;
    c->state[4] += E;
}

static __always_inline void sha1_update(struct sha1 *c, const __u8 *data, __u32 len)
{
    __u32 idx  = c->count & 63;
    __u32 part = HMAC_SHA1_BLOCK_SIZE - idx;
    c->count += len;

    if (len >= part) {
        for (__u32 i = 0; i < len; i++)
            c->buf[idx + i] = data[i];
        sha1_compress(c, c->buf);
        data += part;
        len  -= part;

#pragma clang loop unroll(disable)
        for (; len >= HMAC_SHA1_BLOCK_SIZE; len -= HMAC_SHA1_BLOCK_SIZE, data += HMAC_SHA1_BLOCK_SIZE)
            sha1_compress(c, data);
        idx = 0;
    }

#pragma clang loop unroll(disable)
    for (__u32 i = 0; i < len; i++)
        c->buf[idx + i] = data[i];
}

static __always_inline void sha1_final(struct sha1 *c, __u8 digest[HMAC_SHA1_DIGEST_LEN])
{
    __u8  pad[HMAC_SHA1_BLOCK_SIZE] = { 0x80 };
    __u64 bitlen = c->count << 3;
    __u32 idx    = c->count & 63;
    __u32 padlen = (idx < 56) ? (56 - idx) : (120 - idx);

    sha1_update(c, pad, padlen);

#pragma clang loop unroll(disable)
    for (__u32 i = 0; i < 8; i++)
        c->buf[56 + i] = (bitlen >> (56 - 8*i)) & 0xFF;
    sha1_compress(c, c->buf);

#pragma clang loop unroll(disable)
    for (__u32 i = 0; i < 5; i++) {
        __u32 t = c->state[i];
        digest[4*i  ] = (t >> 24) & 0xFF;
        digest[4*i+1] = (t >> 16) & 0xFF;
        digest[4*i+2] = (t >>  8) & 0xFF;
        digest[4*i+3] =  t        & 0xFF;
    }
}

static __always_inline void hmac_sha1(const __u8 *key, __u32 keylen,
                                      const __u8 *msg, __u32 msglen,
                                      __u8 out[HMAC_SHA1_DIGEST_LEN])
{
    __u32 zero = 0;
    struct hmac1 *h = bpf_map_lookup_elem(&hmac1_map, &zero);
    if (!h) return;

#pragma clang loop unroll(disable)
    for (__u32 i = 0; i < HMAC_SHA1_BLOCK_SIZE; i++)
        h->k0[i] = (i < keylen ? key[i] : 0);

#pragma clang loop unroll(disable)
    for (__u32 i = 0; i < HMAC_SHA1_BLOCK_SIZE; i++) {
        h->ipad[i] = h->k0[i] ^ 0x36;
        h->opad[i] = h->k0[i] ^ 0x5c;
    }

    struct sha1 ctx;
    sha1_init(&ctx);
    sha1_update(&ctx, h->ipad, HMAC_SHA1_BLOCK_SIZE);
    sha1_update(&ctx, msg,   msglen);
    sha1_final (&ctx, h->tmp);

    sha1_init(&ctx);
    sha1_update(&ctx, h->opad, HMAC_SHA1_BLOCK_SIZE);
    sha1_update(&ctx, h->tmp,  HMAC_SHA1_DIGEST_LEN);
    sha1_final (&ctx, out);
}

#endif /* __SEG6_HMAC_SHA1_H */