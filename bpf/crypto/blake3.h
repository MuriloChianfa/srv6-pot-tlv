#ifndef __SEG6_BLAKE3_H
#define __SEG6_BLAKE3_H

#include <linux/types.h>

/* BLAKE3 domain flags */
#define BLAKE3_CHUNK_START  (1 << 0)
#define BLAKE3_CHUNK_END    (1 << 1)
#define BLAKE3_ROOT         (1 << 3)
#define BLAKE3_KEYED_HASH   (1 << 4)

#define BLAKE3_DIGEST_LEN 32

/* Rotate right (32-bit) */
#define ROTR32(x, r) (((x) >> (r)) | ((x) << (32 - (r))))

/* BLAKE3 IV constants */
static const __u32 BLAKE3_IV[8] = {
    0x6A09E667u, 0xBB67AE85u, 0x3C6EF372u, 0xA54FF53Au,
    0x510E527Fu, 0x9B05688Cu, 0x1F83D9ABu, 0x5BE0CD19u
};

/* BLAKE3 gfunction one round diagonal mixing */
static __always_inline void gfunction(__u32 v[16], int a, int b, int c, int d, __u32 x, __u32 y)
{
    v[a] = v[a] + v[b] + x;
    v[d] = ROTR32(v[d] ^ v[a], 16);
    v[c] = v[c] + v[d];
    v[b] = ROTR32(v[b] ^ v[c], 12);
    v[a] = v[a] + v[b] + y;
    v[d] = ROTR32(v[d] ^ v[a], 8);
    v[c] = v[c] + v[d];
    v[b] = ROTR32(v[b] ^ v[c], 7);
}

static __always_inline void blake3_keyed_hash(const __u8 *msg, __u32 len, const __u8 key[32], __u8 out[BLAKE3_DIGEST_LEN])
{
    __u32 v[16];

    const __u32 *key32 = (const __u32 *)__builtin_assume_aligned(key, 4);
#pragma clang loop unroll(full)
    for (__u32 i = 0; i < 8; i++) {
        v[i] = key32[i];
    }

    v[8] = 0;
    v[9] = 0;
    v[10] = 0;
    v[11] = 0;
    v[12] = len;
    v[13] = 0;
    v[14] = (BLAKE3_CHUNK_START | BLAKE3_CHUNK_END | BLAKE3_ROOT | BLAKE3_KEYED_HASH);
    v[15] = 0;

    __u32 m[16];
#pragma clang loop unroll(full)
    for (__u32 i = 0; i < 16; i++) {
        __u32 word = 0;
        __u32 offset = i * 4;
        if (offset + 4 <= len) {
            const __u32 *msg32 = (const __u32 *)__builtin_assume_aligned(msg, 4);
            word = msg32[i];
        } else if (offset < len) {
            const __u8 *p = msg + offset;
            __u32 tmp = 0;
            if (offset + 0 < len) tmp |= ((__u32)p[0] <<  0);
            if (offset + 1 < len) tmp |= ((__u32)p[1] <<  8);
            if (offset + 2 < len) tmp |= ((__u32)p[2] << 16);
            if (offset + 3 < len) tmp |= ((__u32)p[3] << 24);
            word = tmp;
        }
        m[i] = word;
    }

#pragma clang loop unroll(full)
    for (__u32 round = 0; round < 7; round++) {
        static const int sigma[7][16] = {
            { 0, 1, 2, 3,   4, 5, 6, 7,   8, 9,10,11,  12,13,14,15 },
            { 2, 6, 3,10,   7, 0, 4,13,   1,11,12, 5,   9,14,15, 8 },
            { 3, 4,10,12,  13, 2, 7,14,   6,15, 9, 0,  11, 8, 5, 1 },
            {10, 7,12, 9,  14, 3, 6, 5,  15,11, 8, 2,   4, 1, 0,13 },
            {12, 6, 9,14,  11,10,15, 4,   3, 7, 0, 5,  13, 2, 8, 1 },
            { 9,15,14,13,   6,12, 2,10,   7, 8, 1, 4,   5, 3,11, 0 },
            {14,10, 8, 1,  15, 9, 3,13,   4, 0, 5, 6,   2,12,11, 7 }
        };

        const int *s = sigma[round];

        gfunction(v,  0,  4,  8, 12, m[s[ 0]], m[s[ 1]]);
        gfunction(v,  1,  5,  9, 13, m[s[ 2]], m[s[ 3]]);
        gfunction(v,  2,  6, 10, 14, m[s[ 4]], m[s[ 5]]);
        gfunction(v,  3,  7, 11, 15, m[s[ 6]], m[s[ 7]]);
        gfunction(v,  0,  5, 10, 15, m[s[ 8]], m[s[ 9]]);
        gfunction(v,  1,  6, 11, 12, m[s[10]], m[s[11]]);
        gfunction(v,  2,  7,  8, 13, m[s[12]], m[s[13]]);
        gfunction(v,  3,  4,  9, 14, m[s[14]], m[s[15]]);
    }

#pragma clang loop unroll(full)
    for (__u32 i = 0; i < 8; i++) {
        __u32 out_word = v[i] ^ v[i + 8];
        out[4*i + 0] = (out_word >>  0) & 0xFF;
        out[4*i + 1] = (out_word >>  8) & 0xFF;
        out[4*i + 2] = (out_word >> 16) & 0xFF;
        out[4*i + 3] = (out_word >> 24) & 0xFF;
    }
}

#endif /* __SEG6_BLAKE3_H */