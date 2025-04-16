#ifndef __SEG6_KEYS_H
#define __SEG6_KEYS_H

#include <linux/in6.h>
#include <linux/types.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "srh.h"
#include "tlv.h"

#define SEG6_MAX_KEYS SRH_MAX_ALLOWED_SEGMENTS

struct pot_sid_key {
    __u8 key[32];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct in6_addr));
    __uint(value_size, sizeof(struct pot_sid_key));
    __uint(max_entries, SEG6_MAX_KEYS);
} seg6_pot_tlv_keys SEC(".maps");

static __always_inline int chain_keys(struct blake3_pot_tlv *tlv, struct srh *srh, void *end)
{
    __u32 segment_id_size = srh_hdr_len(srh) / IPV6_LEN;
    if ((void *)((__u8 *)srh + SRH_FIXED_HDR_LEN + (IPV6_LEN * segment_id_size)) > end) {
        bpf_printk("[seg6_pot_tlv][-] SRH segments out-of-bounds");
        return -1;
    }

#pragma clang loop unroll(disable)
    for (__u32 i = 0; i < SEG6_MAX_KEYS; i++) {
        if (i >= segment_id_size) return -1;

        __u32 segment_offset = SRH_FIXED_HDR_LEN + (IPV6_LEN * i);
        if ((void *)((__u8 *)srh + segment_offset + IPV6_LEN) > end) {
            bpf_printk("[seg6_pot_tlv][-] SID %u extends beyond packet", i);
            return -1;
        }

        struct in6_addr sid;
        __builtin_memcpy(&sid, (__u8 *)srh + segment_offset, IPV6_LEN);

        struct pot_sid_key *pot_sid_key = bpf_map_lookup_elem(&seg6_pot_tlv_keys, &sid);
        if (!pot_sid_key) {
            bpf_printk("[seg6_pot_tlv][-] Cannot retrieve key for SID %02x%02x:%02x%02x:%02x%02x:%02x%02x",
                sid.s6_addr[0], sid.s6_addr[1], sid.s6_addr[2], sid.s6_addr[3],
                sid.s6_addr[4], sid.s6_addr[5], sid.s6_addr[6], sid.s6_addr[7]);
            bpf_printk("\t\t\t\t\t\t...%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                sid.s6_addr[8],  sid.s6_addr[9],  sid.s6_addr[10], sid.s6_addr[11],
                sid.s6_addr[12], sid.s6_addr[13], sid.s6_addr[14], sid.s6_addr[15]);
            return -1;
        }

        compute_tlv(tlv, pot_sid_key->key);
    }

    return 0;
}

#endif /* __SEG6_KEYS_H */