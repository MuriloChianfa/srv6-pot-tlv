#ifndef __SEG6_MERKLE_LEAVES_H
#define __SEG6_MERKLE_LEAVES_H

#include <linux/types.h>

#include "crypto/keys.h"
#include "crypto/blake3.h"
#include "merkle/tree.h"
#include "srh.h"

#define LEAF_INPUT_LEN (IPV6_LEN + 4 + NONCE_LEN)

static __always_inline int compute_merkle_leaves(struct __sk_buff *skb, struct srh *srh, __u32 segments_cnt, __u8 *leaves[SRH_MAX_ALLOWED_SEGMENTS][BLAKE3_DIGEST_LEN], __u8 *nonce, void *data, void *end)
{
#pragma clang loop unroll(full)
    for (__u32 i = 0; i < SRH_MAX_ALLOWED_SEGMENTS; ++i) {
        if (i < segments_cnt) {
            __u8 sid[IPV6_LEN];
            bpf_skb_load_bytes(skb, (void*)&srh->segments[i*IPV6_LEN] - data, sid, IPV6_LEN);
            if ((void*)&srh->segments[i*IPV6_LEN] - data + 1 > end) {
                continue;
            }

            // construct leaf_input = SID ∥ BE32(i) ∥ nonce
            __u8 leaf_in[LEAF_INPUT_LEN];
#pragma clang loop unroll(full)
            for (__u32 bit = 0; bit < IPV6_LEN; bit++)
                leaf_in[bit] = sid[bit];

            leaf_in[16] = (i >> 24) & 0xFF;
            leaf_in[17] = (i >> 16) & 0xFF;
            leaf_in[18] = (i >>  8) & 0xFF;
            leaf_in[19] = (i <<  0) & 0xFF;

#pragma clang loop unroll(full)
            for (__u32 bit = 0; bit < NONCE_LEN; bit++)
                leaf_in[20 + bit] = nonce[bit];

            // keyed‑hash with hop_keys[i]
            // struct pot_sid_key *pot_sid_key = bpf_map_lookup_elem(&seg6_pot_keys, sid);
            // if (!pot_sid_key) {
            //     bpf_printk("[seg6_pot_tlv][-] Cannot retrieve key for SID %pI6", sid);
            //     return -1;
            // }
            struct pot_sid_key pot_sid_key = {
                .key = {0, 0, 0, 0, 3, 0, 0, 2, 1, 0, 0, 0, 0, 0, 0, 0, 6, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0}
            };

            blake3_keyed_hash(leaf_in, LEAF_INPUT_LEN, &pot_sid_key.key, leaves[i]);
        }
    }

    return 0;
}

#endif /* __SEG6_MERKLE_LEAVES_H */