#ifndef __SEG6_MERKLE_WITNESS_H
#define __SEG6_MERKLE_WITNESS_H

#include <linux/types.h>

#include "crypto/blake3.h"
#include "srh.h"

static __always_inline void compute_merkle_witness(__u8 leaves[SRH_MAX_ALLOWED_SEGMENTS][BLAKE3_DIGEST_LEN], __u32 segments_cnt, __u8 proof_xor[BLAKE3_DIGEST_LEN])
{
    // TODO: abstract merkle tree creation
    __u8 tree[MERKLE_PARENT_IDX_OFFSET * SRH_MAX_ALLOWED_SEGMENTS][BLAKE3_DIGEST_LEN];

    // Populate tree with the leaves
#pragma clang loop unroll(disable)
    for (__u32 segment_index = 0; segment_index < SRH_MAX_ALLOWED_SEGMENTS; segment_index++) {
#pragma clang loop unroll(full)
        for (__u32 bit = 0; bit < BLAKE3_DIGEST_LEN; bit++)
            tree[SRH_MAX_ALLOWED_SEGMENTS + segment_index][bit] = (segment_index < segments_cnt) ? leaves[segment_index][bit] : 0;
    }

    // Build internal tree
#pragma clang loop unroll(disable)
    for (__u32 segment_index = SRH_MAX_ALLOWED_SEGMENTS-1; segment_index > 0; segment_index--) {
        __u8 buffer[BLAKE3_DIGEST_LEN * MERKLE_PARENT_IDX_OFFSET];

#pragma clang loop unroll(full)
        for (__u32 bit = 0; bit < BLAKE3_DIGEST_LEN; bit++) {
            buffer[bit] = tree[MERKLE_PARENT_IDX_OFFSET * segment_index][bit];
            buffer[BLAKE3_DIGEST_LEN + bit] = tree[(MERKLE_PARENT_IDX_OFFSET * segment_index) + MERKLE_NEXT_IDX][bit];
        }

        // TODO: implement blake3 hash function
        blake3_hash(buffer, BLAKE3_DIGEST_LEN * MERKLE_PARENT_IDX_OFFSET, tree[segment_index]);
    }

    // OR‑aggregate siblings
#pragma clang loop unroll(disable)
    for (__u32 bit = 0; bit < BLAKE3_DIGEST_LEN; bit++)
        proof_xor[bit] = 0;

#pragma clang loop unroll(disable)
    for (__u32 leaf = 0; leaf < segments_cnt; leaf++) {
        __u32 idx = SRH_MAX_ALLOWED_SEGMENTS + leaf;

#pragma clang loop unroll(disable)
        for (__u32 level = 0; level < DEPTH; level++) {
            __u32 sib = idx ^ MERKLE_NEXT_IDX;

#pragma clang loop unroll(full)
            for (__u32 sib_bit = 0; sib_bit < BLAKE3_DIGEST_LEN; sib_bit++)
                proof_xor[sib_bit] ^= tree[sib][sib_bit];

            idx >>= MERKLE_NEXT_IDX;
        }
    }
}

#endif /* __SEG6_MERKLE_WITNESS_H */