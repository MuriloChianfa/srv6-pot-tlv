#ifndef __SEG6_TLV_ADD_H
#define __SEG6_TLV_ADD_H

#include <linux/in6.h>
#include <linux/types.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "crypto/keys.h"
#include "tlv.h"
#include "hdr.h"

static __always_inline int add_pot_tlv(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *end = (void *)(long)skb->data_end;

    struct ethhdr *eth = ETH_HDR_PTR;
    struct ipv6hdr *ipv6 = IPV6_HDR_PTR;
    struct srh *srh = SRH_HDR_PTR;

    eth = ETH_HDR_PTR;
    if (eth_hdr_cb(eth, end) < 0)
        return -1;

    ipv6 = IPV6_HDR_PTR;
    if (ip6_hdr_cb(ipv6, end) < 0)
        return -1;

    srh = SRH_HDR_PTR;
    if (srh_hdr_cb(srh, end) < 0)
        return -1;

    __u32 segment_size = calc_segment_size(srh, end);
    if (segment_size == 0) return -1;

    struct srh foresrh = {
        .next_hdr = srh->next_hdr,
        .hdr_ext_len = srh->hdr_ext_len,
        .routing_type = srh->routing_type,
        .segments_left = srh->segments_left,
        .last_entry = srh->last_entry,
        .flags = srh->flags,
        .tag = srh->tag
    };

    struct in6_addr *sidlist;
    __u32 sidmap_key = 0;
    sidlist = bpf_map_lookup_elem(&sidmap, &sidmap_key);
    if (!sidlist) return -1;

    __u32 max_segments = SRH_MAX_ALLOWED_SEGMENTS;
    if (segment_size > max_segments) {
        bpf_printk("[seg6_pot_tlv][-] SRH segment size exceeds max allowed");
        return -1;
    }

    if (retrieve_sidlist(sidlist, srh, segment_size, end) < 0) {
        bpf_printk("[seg6_pot_tlv][-] Failed to retrieve SID list");
        return -1;
    }

    if (bpf_skb_adjust_room(skb, POT_TLV_WIRE_LEN, BPF_ADJ_ROOM_NET, 0) < 0) {
        bpf_printk("[seg6_pot_tlv][-] Failed to adjust L3 room");
        return -1;
    }

    if (bpf_skb_store_bytes(skb, SRH_HDR_OFFSET, &foresrh, SRH_FIXED_HDR_LEN, BPF_F_RECOMPUTE_CSUM) < 0) {
        bpf_printk("[seg6_pot_tlv][-] bpf_skb_store_bytes failed realocate srh");
        return -1;
    }

    for (__u32 i = 0; i < segment_size; i++) {
		if (i >= SRH_MAX_ALLOWED_SEGMENTS) break;

        __u32 segment_offset = SRH_FIXED_HDR_LEN + (IPV6_LEN * (__u32)i);
        if ((void *)((__u8 *)srh + segment_offset + IPV6_LEN) > end) {
            bpf_printk("[seg6_pot_tlv][-] SID %u extends beyond packet", i);
            return -1;
        }

		if (bpf_skb_store_bytes(skb, SRH_HDR_OFFSET + segment_offset, &sidlist[i], IPV6_LEN, 0) < 0) {
            bpf_printk("[seg6_pot_tlv][-] bpf_skb_store_bytes failed realocate sid list");
			return -1;
		}
	}

    data = (void *)(long)skb->data;
    end = (void *)(long)skb->data_end;

    eth = ETH_HDR_PTR;
    if (eth_hdr_cb(eth, end) < 0)
        return -1;

    ipv6 = IPV6_HDR_PTR;
    if (ip6_hdr_cb(ipv6, end) < 0)
        return -1;

    srh = SRH_HDR_PTR;
    if (srh_hdr_cb(srh, end) < 0)
        return -1;

    struct pot_tlv tlv;
    init_tlv(&tlv);

    if (chain_keys(&tlv, srh, end) < 0) {
        bpf_printk("[seg6_pot_tlv][-] chain_keys failed");
        return -1;
    }

    zerofy_witness(&tlv);

    __u32 tlv_offset = SRH_HDR_OFFSET + SRH_FIXED_HDR_LEN + (IPV6_LEN * (__u32)segment_size);
    if ((void *)data + tlv_offset + POT_TLV_WIRE_LEN > end) {
        bpf_printk("[seg6_pot_tlv][-] not enough space in packet buffer for TLV");
        return -1;
    }

    if (bpf_skb_store_bytes(skb, tlv_offset, &tlv, POT_TLV_WIRE_LEN, BPF_F_RECOMPUTE_CSUM) < 0) {
        bpf_printk("[seg6_pot_tlv][-] bpf_skb_store_bytes failed to write the new TLV");
        return -1;
    }

    if (recalc_skb_ip6_tlv_len(skb, POT_TLV_WIRE_LEN) < 0) {
        bpf_printk("[seg6_pot_tlv][-] recalc_skb_ip6_tlv_len failed");
        return -1;
    }

    if (recalc_skb_tlv_len(skb, POT_TLV_EXT_LEN) < 0) {
        bpf_printk("[seg6_pot_tlv][-] recalc_skb_tlv_len failed");
        return -1;
    }

    return 0;
}

#endif /* __SEG6_TLV_ADD_H */