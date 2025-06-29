#ifndef __SEG6_KEYS_H
#define __SEG6_KEYS_H

#include <linux/in6.h>
#include <linux/types.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "srh.h"
#include "tlv.h"
#include "sid.h"

#define SEG6_KEY_LEN 32
#define SEG6_MAX_KEYS SRH_MAX_ALLOWED_SEGMENTS

struct pot_sid_key {
    __u8 key[SEG6_KEY_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct in6_addr));
    __uint(value_size, sizeof(struct pot_sid_key));
    __uint(max_entries, SEG6_MAX_KEYS);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} seg6_pot_keys SEC(".maps");

static __always_inline int compute_witness(struct in6_addr *ip6, struct pot_tlv *tlv)
{
    struct pot_sid_key *pot_sid_key = bpf_map_lookup_elem(&seg6_pot_keys, ip6->s6_addr);
    if (!pot_sid_key) {
        bpf_printk("[seg6_pot_tlv][-] Cannot retrieve key for SID %pI6", ip6->s6_addr);
        return -1;
    }

    bpf_printk("[seg6_pot_tlv][*] Computing keyed-hash for SID %pI6", ip6->s6_addr);
    compute_tlv(tlv, pot_sid_key->key);

    bpf_printk("[seg6_pot_tlv][*] keyed-hash calculated for witness");
    return 0;
}

#if ISADDR
static __always_inline int compute_first_witness(struct ipv6hdr *ipv6, struct pot_tlv *tlv)
{
    struct in6_addr sid;
    __builtin_memcpy(&sid, &ipv6->saddr.in6_u, IPV6_LEN);

    return compute_witness(&sid, tlv);
}
#endif

static __always_inline int compute_witness_once(struct pot_tlv *tlv, struct srh *srh, void *end)
{
    __u32 segment_size = srh_hdr_len(srh) / IPV6_LEN;
    if ((void *)((__u8 *)srh + SRH_FIXED_HDR_LEN + (IPV6_LEN * segment_size)) > end) {
        bpf_printk("[seg6_pot_tlv][-] SRH segments out-of-bounds");
        return -1;
    }

    __u32 idx = srh->last_entry - srh->segments_left;
    idx = srh->last_entry - idx;
    if (idx < 0 || idx > segment_size)
        return -1;

    __u32 segment_offset = SRH_FIXED_HDR_LEN + (IPV6_LEN * idx);
    if ((void *)((__u8 *)srh + segment_offset + IPV6_LEN) > end) {
        bpf_printk("[seg6_pot_tlv][-] SID %u extends beyond packet", idx);
        return -1;
    }

    struct in6_addr sid;
    __builtin_memcpy(&sid, (__u8 *)srh + segment_offset, IPV6_LEN);

    return compute_witness(&sid, tlv);
}

static __always_inline int chain_keys(struct srh *srh, struct pot_tlv *tlv, void *end)
{
    __u32 segment_size = srh_hdr_len(srh) / IPV6_LEN;
    if ((void *)((__u8 *)srh + SRH_FIXED_HDR_LEN + (IPV6_LEN * segment_size)) > end) {
        bpf_printk("[seg6_pot_tlv][-] SRH segments out-of-bounds");
        return -1;
    }

#pragma clang loop unroll(disable)
    for (__s16 i = SEG6_MAX_KEYS; i >= 0; i--) {
        if (i < 0) i = 0;
        if ((__u32)i >= segment_size) continue;

        __u32 segment_offset = SRH_FIXED_HDR_LEN + (IPV6_LEN * (__u32)i);
        if ((void *)((__u8 *)srh + segment_offset + IPV6_LEN) > end) {
            bpf_printk("[seg6_pot_tlv][-] SID %u extends beyond packet", i);
            return -1;
        }

        struct in6_addr sid;
        __builtin_memcpy(&sid, (__u8 *)srh + segment_offset, IPV6_LEN);

        if (compute_witness(&sid, tlv)) {
            bpf_printk("[seg6_pot_tlv][-] Cannot compute witness for SID %pI6", sid.s6_addr);
            return -1;
        }
    }

    bpf_printk("[seg6_pot_tlv][*] keyed-hash calculated to each SID successfully");
    return 0;
}

#endif /* __SEG6_KEYS_H */