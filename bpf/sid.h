#ifndef __SEG6_SID_H
#define __SEG6_SID_H

#include <linux/in6.h>
#include <linux/types.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define SRH_MAX_ALLOWED_SEGMENTS 8

#include "srh.h"

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct in6_addr[SRH_MAX_ALLOWED_SEGMENTS]);
} sidmap SEC(".maps");

static __always_inline __u32 calc_segment_size(struct srh *srh, void *end)
{
    __u32 segment_size = srh_hdr_len(srh) / IPV6_LEN;
    if ((void *)((__u8 *)srh + SRH_HDR_LEN(segment_size)) > end) {
        bpf_printk("[seg6_pot_tlv][-] SRH segments out-of-bounds");
        return 0;
    }

    if (srh->hdr_ext_len & 1) {
        bpf_printk("[seg6_pot_tlv][-] SRH hdr_ext_len isn't even");
        return 0;
    }

    if (segment_size > SRH_MAX_ALLOWED_SEGMENTS) {
        bpf_printk("[seg6_pot_tlv][-] Too many SRH segments: %u\n", segment_size);
        return 0;
    }

    return segment_size;
}

static __always_inline int retrieve_sidlist(struct in6_addr *sidlist, struct srh *srh, __u32 segment_size, void *end)
{
#pragma clang loop unroll(full)
    for (__s16 i = SRH_MAX_ALLOWED_SEGMENTS; i >= 0; i--) {
        if (i < 0) i = 0;
        if ((__u32)i >= segment_size) continue;

        __u32 segment_offset = SRH_FIXED_HDR_LEN + (IPV6_LEN * (__u32)i);
        if ((void *)((__u8 *)srh + segment_offset + IPV6_LEN) > end) {
            bpf_printk("[seg6_pot_tlv][-] SID %u extends beyond packet", i);
            return -1;
        }

        __builtin_memcpy(&sidlist[i], (__u8 *)srh + segment_offset, IPV6_LEN);
    }

    return 0;
}

#endif /* __SEG6_SID_H */