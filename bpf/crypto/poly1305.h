#ifndef __SEG6_POLY1305_H
#define __SEG6_POLY1305_H

#include <linux/types.h>
#include <bpf/bpf_helpers.h> // Include for bpf_map_lookup_elem

#define POLY1305_TAG_LEN 16

/* Clamp masks for Poly1305 r key */
#define CLAMP_MASK_0 0x0FFFFFFF
#define CLAMP_MASK_1 0x0FFFFFFF
#define CLAMP_MASK_2 0x0FFFFFFC
#define CLAMP_MASK_3 0x0FFFFFFC

/* Prime constants for Poly1305 */
#define P0 0xFFFFFFFB
#define P1 0xFFFFFFFF
#define P2 0xFFFFFFFF
#define P3 0xFFFFFFFF
#define P4 0x00000003

// Define scratch space structure and map
struct scratch_space {
    __u8 buf[128]; // Accommodates t[10] (__u64) = 80 bytes and block[5] (__u32) = 20 bytes
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct scratch_space));
    __uint(max_entries, 1);
} poly1305_scratch SEC(".maps");

struct poly1305_acc {
    __u32 r[5];
};

/* 32-bit multiplication with carry */
static inline void mul32x32(__u64 *high, __u64 *low, __u32 a, __u32 b)
{
    __u64 prod = (__u64)a * b;

    *low = prod & 0xFFFFFFFF;
    *high = prod >> 32;
}

/* Add two 130-bit - 5 numbers */
static inline void add_130(struct poly1305_acc *acc, __u32 *b)
{
    __u64 sum = 0;

#pragma clang loop unroll(full)
    for (__u8 i = 0; i < 5; i++) {
        sum = (__u64)acc->r[i] + b[i] + (sum >> 32);
        acc->r[i] = sum & 0xFFFFFFFF;
    }
}

/* Multiply accumulator by r and reduce modulo 2^130 - 5 */
static inline int mul_mod_p(struct poly1305_acc *acc, __u32 *r) // Return int for error checking
{
    __u64 carry;
    __u32 key = 0;
    struct scratch_space *scratch;
    __u64 *t; // Pointer to scratch space

    scratch = bpf_map_lookup_elem(&poly1305_scratch, &key);
    if (!scratch) {
        return -1;
    }
    // Zero the part of the scratch buffer used for 't'
    __builtin_memset(scratch->buf, 0, 10 * sizeof(__u64));
    t = (__u64 *)scratch->buf;

    // Compute t = acc * r
#pragma clang loop unroll(full)
    for (__u8 i = 0; i < 5; i++) {
#pragma clang loop unroll(full)
        for (int j = 0; j < 5; j++) {
            __u64 high, low;
            if (i < 5 && j < 5) {
                mul32x32(&high, &low, acc->r[i], r[j]);
                if (i + j < 10) {
                    t[i + j] += low;
                }
                if (i + j + 1 < 10) {
                    t[i + j + 1] += high;
                }
            }
        }
    }

    // Propagate carries
#pragma clang loop unroll(full)
    for (__u8 i = 0; i < 9; i++) {
        if (i < 10 && i + 1 < 10) {
            t[i + 1] += t[i] >> 32;
            t[i] &= 0xFFFFFFFF;
        }
    }
    if (9 < 10) {
        t[9] &= 0xFFFFFFFF;
    }

    // Fold high part into low part (modulo 2^130-5)
#pragma clang loop unroll(full)
    for (__u8 i = 0; i < 5; i++) {
        if (i < 10 && i < 5) {
            acc->r[i] = (__u32)t[i];
        }
    }
#pragma clang loop unroll(full)
    for (__u8 i = 5; i < 10; i++) {
        if (i < 10 && i - 5 < 5) {
            __u64 v = t[i] * 5;
            acc->r[i - 5] += (v & 0xFFFFFFFF);
            if (i - 5 + 1 < 5)
                acc->r[i - 5 + 1] += (v >> 32);
        }
    }

    // Final carry propagation
    carry = 0;
#pragma clang loop unroll(full)
    for (__u8 i = 0; i < 5; i++) {
        if (i < 5) {
            __u64 sum = (__u64)acc->r[i] + carry;
            acc->r[i] = (__u32)sum;
            carry = sum >> 32;
        }
    }
    return 0; // Success
}

/* Final reduction modulo 2^130 - 5 */
static inline void reduce_final(struct poly1305_acc *acc) {
    __u32 ge_p = 1;
    const __u32 p[5] = {P0, P1, P2, P3, P4};

    if (acc->r[4] < p[4] ||
        (acc->r[4] == p[4] && acc->r[3] < p[3]) ||
        (acc->r[4] == p[4] && acc->r[3] == p[3] && acc->r[2] < p[2]) ||
        (acc->r[4] == p[4] && acc->r[3] == p[3] && acc->r[2] == p[2] && acc->r[1] < p[1]) ||
        (acc->r[4] == p[4] && acc->r[3] == p[3] && acc->r[2] == p[2] && acc->r[1] == p[1] && acc->r[0] < p[0])) {
        ge_p = 0;
    }

    if (ge_p) {
        __u64 borrow = 0;

#pragma clang loop unroll(full)
        for (__u8 i = 0; i < 5; i++) {
            if (i < 5) {
                __u64 diff = (__u64)acc->r[i] - p[i] - borrow;
                acc->r[i] = diff & 0xFFFFFFFF;
                borrow = (diff >> 63);
            }
        }
    }
}

static inline int poly1305(__u8 *tag, const __u8 *msg, __u32 msg_len, const __u8 *key) // Return int, add msg_len
{
    struct poly1305_acc acc = {{0, 0, 0, 0, 0}};
    __u32 r[5] = {0};
    __u32 s[4];

    // --- Key Setup ---
    r[0] = ((__u32)key[0] ) | ((__u32)key[1] << 8) | ((__u32)key[2] << 16) | ((__u32)key[3] << 24);
    r[1] = ((__u32)key[4] ) | ((__u32)key[5] << 8) | ((__u32)key[6] << 16) | ((__u32)key[7] << 24);
    r[2] = ((__u32)key[8] ) | ((__u32)key[9] << 8) | ((__u32)key[10] << 16) | ((__u32)key[11] << 24);
    r[3] = ((__u32)key[12]) | ((__u32)key[13] << 8) | ((__u32)key[14] << 16) | ((__u32)key[15] << 24);

    r[0] &= 0x0FFFFFFF;
    r[1] &= 0x0FFFFFFC;
    r[2] &= 0x0FFFFFFC;
    r[3] &= 0x0FFFFFFC;

    s[0] = ((__u32)key[16]) | ((__u32)key[17] << 8) | ((__u32)key[18] << 16) | ((__u32)key[19] << 24);
    s[1] = ((__u32)key[20]) | ((__u32)key[21] << 8) | ((__u32)key[22] << 16) | ((__u32)key[23] << 24);
    s[2] = ((__u32)key[24]) | ((__u32)key[25] << 8) | ((__u32)key[26] << 16) | ((__u32)key[27] << 24);
    s[3] = ((__u32)key[28]) | ((__u32)key[29] << 8) | ((__u32)key[30] << 16) | ((__u32)key[31] << 24);

    // --- Process Message ---
    __u32 key_idx = 0;
    struct scratch_space *scratch;
    __u32 *block;

    scratch = bpf_map_lookup_elem(&poly1305_scratch, &key_idx);
    if (!scratch) {
        return -1;
    }
    block = (__u32 *)(scratch->buf + 80);

    __u32 remaining = msg_len;
    const __u8 *current_msg = msg;

    while (remaining > 0) {
        __u32 block_len = remaining < 16 ? remaining : 16;
        __builtin_memset(block, 0, 5 * sizeof(__u32));

        __u32 i;
        volatile __u8 *p = (__u8*)block;
        for (i = 0; i < block_len; ++i) {
            p[i] = current_msg[i];
        }

        if (i < 16) {
            p[i] = 1;
        }
        block[4] = (block_len == 16);

        add_130(&acc, block);
        if (mul_mod_p(&acc, r) < 0) {
            return -1;
        }

        current_msg += block_len;
        remaining -= block_len;
    }

    // --- Finalization ---
    reduce_final(&acc);

    __u64 carry = 0;
#pragma clang loop unroll(full)
    for (__u8 i = 0; i < 4; i++) {
        if (i < 5) {
            carry = (__u64)acc.r[i] + s[i] + (carry >> 32);
            acc.r[i] = carry & 0xFFFFFFFF;
        }
    }
    if (4 < 5) {
        carry = (__u64)acc.r[4] + (carry >> 32);
        acc.r[4] = carry & 0xFFFFFFFF;
    }

#pragma clang loop unroll(full)
    for (__u8 i = 0; i < 4; i++) {
        if (i < 5 && (i * 4 + 3) < POLY1305_TAG_LEN) {
            tag[i * 4 + 0] = acc.r[i] & 0xFF;
            tag[i * 4 + 1] = (acc.r[i] >> 8) & 0xFF;
            tag[i * 4 + 2] = (acc.r[i] >> 16) & 0xFF;
            tag[i * 4 + 3] = (acc.r[i] >> 24) & 0xFF;
        }
    }

    return 0; // Success
}

#endif /* __SEG6_POLY1305_H */