#ifndef __SEG6_MERKLE_ROOT_H
#define __SEG6_MERKLE_ROOT_H

#include <linux/types.h>

#include "crypto/blake3.h"
#include "merkle/tree.h"
#include "srh.h"

static __always_inline void compute_merkle_root(__u8 leaves[SRH_MAX_ALLOWED_SEGMENTS][BLAKE3_DIGEST_LEN], __u32 segments_cnt, __u8 root[BLAKE3_DIGEST_LEN])
{
    // TODO: abstract merkle tree creation
    __u8 tree[2 * SRH_MAX_ALLOWED_SEGMENTS][BLAKE3_DIGEST_LEN];

    // Populare tree with the leaves
#pragma clang loop unroll(disable)
    for (__u32 segment_index = 0; segment_index < SRH_MAX_ALLOWED_SEGMENTS; segment_index++) {
#pragma clang loop unroll(full)
        for (__u32 bit = 0; bit < BLAKE3_DIGEST_LEN; bit++)
            tree[SRH_MAX_ALLOWED_SEGMENTS + segment_index][bit] = (segment_index < segments_cnt) ? leaves[segment_index][bit] : 0;
    }

    // Build internal tree
#pragma clang loop unroll(disable)
    for (__u32 segment_index = SRH_MAX_ALLOWED_SEGMENTS - 1; segment_index > 0; segment_index--) {
        __u8 buffer[BLAKE3_DIGEST_LEN * MERKLE_PARENT_IDX_OFFSET];

#pragma clang loop unroll(full)
        for (__u32 bit = 0; bit < BLAKE3_DIGEST_LEN; bit++) {
            buffer[bit] = tree[MERKLE_PARENT_IDX_OFFSET * segment_index][bit];
            buffer[BLAKE3_DIGEST_LEN + bit] = tree[(MERKLE_PARENT_IDX_OFFSET * segment_index) + MERKLE_NEXT_IDX][bit];
        }

        // TODO: implement blake3 hash function
        blake3_hash(buffer, BLAKE3_DIGEST_LEN * MERKLE_PARENT_IDX_OFFSET, tree[segment_index]);
    }

    // Extract root
#pragma clang loop unroll(full)
    for (__u32 bit = 0; bit < BLAKE3_DIGEST_LEN; bit++)
        root[bit] = tree[MERKLE_ROOT_IDX][bit];
}

#endif /* __SEG6_MERKLE_ROOT_H */