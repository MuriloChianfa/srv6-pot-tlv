#ifndef __SEG6_NONCE_H
#define __SEG6_NONCE_H

#include <linux/types.h>

/* Nonce properties */
#define NONCE_MASK 0xFF
#define NONCE_RANDOMNESS 3
#define NONCE_SHIFTS 2

/* Total Nonce len in bytes */
#define NONCE_LEN (NONCE_RANDOMNESS << NONCE_SHIFTS)

/* Right Shift AND Masked */
#define RSMASKED(r, f) ((r >> f) & NONCE_MASK)

static const __u32 NONCE_PADDING[] = {0, 4, 8};
static const __u32 NONCE_FACTORS[] = {16, 24};

/*
    Nonce generation into BPF little‑endian machines
    0  1  2  3   4  5  6  7     8    9   10   11
   ┌──────────┐ ┌──────────┐ ┌────────────────────┐
   │ r0[0..3] │ | r1[0..3] │ |r2[0..1] r3[2] r4[3]│
   └──────────┘ └──────────┘ └────────────────────┘
*/
static __always_inline void new_nonce(__u8 *nonce)
{
    __u32 x;

#pragma clang loop unroll(full)
    for (__u8 i = 0; i < NONCE_RANDOMNESS; ++i) {
        x = bpf_get_prandom_u32();
        *((__u32*)(nonce + NONCE_PADDING[i])) = x;
    }
#pragma clang loop unroll(full)
    for (__u8 i = 0; i < NONCE_SHIFTS; ++i) {
        nonce[NONCE_LEN -1 -i] = RSMASKED(x, NONCE_FACTORS[i]);
    }
}

#endif /* __SEG6_NONCE_H */