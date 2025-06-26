#ifndef __SEG6_HMAC_SHA256_H
#define __SEG6_HMAC_SHA256_H

#include <linux/types.h>

#define HMAC_SHA256_BLOCK_SIZE 64
#define HMAC_SHA256_DIGEST_LEN 32

/* SHA-256 context */
struct sha256 {
    __u32 state[8];
    __u64 count;
    __u8 buf[64];
};

/* Rotate right (32-bit) */
#define ROTR32(x, r) (((x) >> (r)) | ((x) << (32 - (r))))

/* choice, majority */
#define CH(x,y,z)  ( ((x) & (y)) ^ (~(x) & (z)) )
#define MAJ(x,y,z) ( ((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)) )

/* SHA-256 big and small sigmas */
#define SIG0(x)    ( ROTR32((x),  2) ^ ROTR32((x), 13) ^ ROTR32((x), 22) )
#define SIG1(x)    ( ROTR32((x),  6) ^ ROTR32((x), 11) ^ ROTR32((x), 25) )
#define THETA0(x)  ( ROTR32((x),  7) ^ ROTR32((x), 18) ^ ((x) >>  3) )
#define THETA1(x)  ( ROTR32((x), 17) ^ ROTR32((x), 19) ^ ((x) >> 10) )

/* SHA-256 constants */
static const __u32 K256[64] = {
    0x428a2f98ul,0x71374491ul,0xb5c0fbcful,0xe9b5dba5ul,
    0x3956c25bul,0x59f111f1ul,0x923f82a4ul,0xab1c5ed5ul,
    0xd807aa98ul,0x12835b01ul,0x243185beul,0x550c7dc3ul,
    0x72be5d74ul,0x80deb1feul,0x9bdc06a7ul,0xc19bf174ul,
    0xe49b69c1ul,0xefbe4786ul,0x0fc19dc6ul,0x240ca1ccul,
    0x2de92c6ful,0x4a7484aaul,0x5cb0a9dcul,0x76f988daul,
    0x983e5152ul,0xa831c66dul,0xb00327c8ul,0xbf597fc7ul,
    0xc6e00bf3ul,0xd5a79147ul,0x06ca6351ul,0x14292967ul,
    0x27b70a85ul,0x2e1b2138ul,0x4d2c6dfcul,0x53380d13ul,
    0x650a7354ul,0x766a0abbul,0x81c2c92eul,0x92722c85ul,
    0xa2bfe8a1ul,0xa81a664bul,0xc24b8b70ul,0xc76c51a3ul,
    0xd192e819ul,0xd6990624ul,0xf40e3585ul,0x106aa070ul,
    0x19a4c116ul,0x1e376c08ul,0x2748774cul,0x34b0bcb5ul,
    0x391c0cb3ul,0x4ed8aa4aul,0x5b9cca4ful,0x682e6ff3ul,
    0x748f82eeul,0x78a5636ful,0x84c87814ul,0x8cc70208ul,
    0x90befffaul,0xa4506cebul,0xbef9a3f7ul,0xc67178f2ul
};

static __always_inline void sha256_init(struct sha256 *c)
{
    c->state[0] = 0x6a09e667ul;
    c->state[1] = 0xbb67ae85ul;
    c->state[2] = 0x3c6ef372ul;
    c->state[3] = 0xa54ff53aul;
    c->state[4] = 0x510e527ful;
    c->state[5] = 0x9b05688cul;
    c->state[6] = 0x1f83d9abul;
    c->state[7] = 0x5be0cd19ul;

    c->count = 0;
}

static __always_inline void sha256_compress(struct sha256 *c, const __u8 data[64])
{
    __s64 w[64], A, B, C, D, E, F, G, H, T1, T2;

#pragma clang loop unroll(full)
    for (__u32 i = 0; i < 16; i++)
        w[i] = (data[4*i] << 24) | (data[4*i+1] << 16)
           | (data[4*i+2] << 8)  | (data[4*i+3]);
#pragma clang loop unroll(disable)
    for (__u32 i = 16; i < 64; i++)
        w[i] = THETA1(w[i-2]) + w[i-7] + THETA0(w[i-15]) + w[i-16];

    A = c->state[0]; B = c->state[1];
    C = c->state[2]; D = c->state[3];
    E = c->state[4]; F = c->state[5];
    G = c->state[6]; H = c->state[7];

#pragma clang loop unroll(disable)
    for (__u32 i = 0; i < 64; i++) {
        T1 = H + SIG1(E) + CH(E,F,G) + K256[i] + w[i];
        T2 = SIG0(A) + MAJ(A,B,C);
        H = G; G = F; F = E;
        E = D + T1;
        D = C; C = B; B = A;
        A = T1 + T2;
    }

    c->state[0] += A;
    c->state[1] += B;
    c->state[2] += C;
    c->state[3] += D;
    c->state[4] += E;
    c->state[5] += F;
    c->state[6] += G;
    c->state[7] += H;
}

static __always_inline void sha256_update(struct sha256 *c, const __u8 *data, __u32 len)
{
    __u32 idx = c->count & 63;
    __u32 part = 64 - idx;

    c->count += len;

    if (len >= part) {
#pragma clang loop unroll(disable)
        for (__u32 i = 0; i < part; i++)
            c->buf[idx + i] = data[i];

        sha256_compress(c, c->buf);
        data += part; len -= part;

#pragma clang loop unroll(disable)
        for (; len >= 64; len -= 64, data += 64)
            sha256_compress(c, data);

        idx = 0;
    }

#pragma clang loop unroll(disable)
    for (__u32 i = 0; i < len; i++)
        c->buf[idx + i] = data[i];
}

static __always_inline void sha256_final(struct sha256 *c, __u8 digest[32])
{
    __u8  pad[64] = { 0x80 };
    __u64 bitlen = c->count << 3;
    __u32 idx    = c->count & 63;
    __u32 padlen = (idx < 56) ? (56 - idx) : (120 - idx);

    sha256_update(c, pad, padlen);

#pragma clang loop unroll(full)
    for (__u32 i = 0; i < 8; i++)
        c->buf[56 + i] = (bitlen >> (56 - 8*i)) & 0xFF;

    sha256_compress(c, c->buf);

#pragma clang loop unroll(full)
    for (__u32 i = 0; i < 8; i++) {
        __u32 t = c->state[i];

        digest[4*i  ] = (t >> 24) & 0xFF;
        digest[4*i+1] = (t >> 16) & 0xFF;
        digest[4*i+2] = (t >>  8) & 0xFF;
        digest[4*i+3] =  t        & 0xFF;
    }
}

static __always_inline void hmac_sha256(const __u8 *key, __u32 keylen, const __u8 *msg, __u32 msglen, __u8 out[HMAC_SHA256_DIGEST_LEN])
{
    __u8 k0[HMAC_SHA256_BLOCK_SIZE];
    __u8 tmp[HMAC_SHA256_DIGEST_LEN];
    __u8 ipad[HMAC_SHA256_BLOCK_SIZE];
    __u8 opad[HMAC_SHA256_BLOCK_SIZE];

    struct sha256 sha256;

#pragma clang loop unroll(full)
    for (__u32 i = 0; i < HMAC_SHA256_BLOCK_SIZE; i++)
        k0[i] = (i < keylen ? key[i] : 0);

#pragma clang loop unroll(full)
    for (__u32 i = 0; i < HMAC_SHA256_BLOCK_SIZE; i++) {
        ipad[i] = k0[i] ^ 0x36;
        opad[i] = k0[i] ^ 0x5c;
    }

    sha256_init(&sha256);
    sha256_update(&sha256, ipad, HMAC_SHA256_BLOCK_SIZE);
    sha256_update(&sha256, msg, msglen);
    sha256_final(&sha256, tmp);

    sha256_init(&sha256);
    sha256_update(&sha256, opad, HMAC_SHA256_BLOCK_SIZE);
    sha256_update(&sha256, tmp, HMAC_SHA256_DIGEST_LEN);
    sha256_final(&sha256, out);
}

#endif /* __SEG6_HMAC_SHA256_H */