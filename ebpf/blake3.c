#include <blake3.h>

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

static __always_inline void blake3_hash(const __u8 *msg, __u32 msg_len, __u8 out[32])
{
    __u32 v[16];
#pragma clang loop unroll(full)
    for (__u32 i = 0; i < 8; i++)
        v[i] = BLAKE3_IV[i];
    v[8]  = 0;
    v[9]  = 0;
    v[10] = 0;
    v[11] = 0;
    v[12] = msg_len;
    v[13] = 0;
    v[14] = 0x07; // _START | _END | _ROOT
    v[15] = 0;

    __u32 m[16];

#pragma clang loop unroll(full)
    for (__u32 i = 0; i < 16; i++) {
        __u32 w = 0;
        if ((i * 4) < msg_len) {
            const __u8 *p = msg + i * 4;
            __u32 tmp = 0;
            if ((i * 4) + 0 < msg_len)
                tmp |= ((__u32)p[0] << 0);
            if ((i * 4) + 1 < msg_len)
                tmp |= ((__u32)p[1] << 8);
            if ((i * 4) + 2 < msg_len)
                tmp |= ((__u32)p[2] << 16);
            if ((i * 4) + 3 < msg_len)
                tmp |= ((__u32)p[3] << 24);
            w = tmp;
        }
        m[i] = w;
    }

#pragma clang loop unroll(full)
    for (__u32 round = 0; round < 7; round++) {
        const int sigma[7][16] = {
            { 0, 1, 2, 3,  4, 5, 6, 7,  8, 9,10,11, 12,13,14,15 },
            { 2, 6, 3,10,  7, 0, 4,13,  1,11,12, 5,  9,14,15, 8 },
            { 3, 4,10,12, 13, 2, 7,14,  6,15, 9, 0, 11, 8, 5, 1 },
            {10, 7,12, 9, 14, 3, 6, 5, 15,11, 8, 2,  4, 1, 0,13 },
            {12, 6, 9,14, 11,10,15, 4,  3, 7, 0, 5, 13, 2, 8, 1 },
            { 9,15,14,13,  6,12, 2,10,  7, 8, 1, 4,  5, 3,11, 0 },
            {14,10, 8, 1, 15, 9, 3,13,  4, 0, 5, 6,  2,12,11, 7 }
        };

        const int *s = sigma[round];

        gfunction(v, 0, 4,  8, 12, m[s[0]],  m[s[1]]);
        gfunction(v, 1, 5,  9, 13, m[s[2]],  m[s[3]]);
        gfunction(v, 2, 6, 10, 14, m[s[4]],  m[s[5]]);
        gfunction(v, 3, 7, 11, 15, m[s[6]],  m[s[7]]);
        gfunction(v, 0, 5, 10, 15, m[s[8]],  m[s[9]]);
        gfunction(v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
        gfunction(v, 2, 7,  8, 13, m[s[12]], m[s[13]]);
        gfunction(v, 3, 4,  9, 14, m[s[14]], m[s[15]]);
    }

#pragma clang loop unroll(full)
    for (__u32 i = 0; i < 8; i++) {
        __u32 out_word = v[i] ^ v[i + 8];

        out[4 * i + 0] = out_word & 0xFF;
        out[4 * i + 1] = (out_word >> 8) & 0xFF;
        out[4 * i + 2] = (out_word >> 16) & 0xFF;
        out[4 * i + 3] = (out_word >> 24) & 0xFF;
    }
}
