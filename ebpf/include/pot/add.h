#ifndef __SEG6_TLV_ADD_H
#define __SEG6_TLV_ADD_H

#include <linux/in6.h>
#include <linux/types.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "crypto/keys.h"
#include "tlv.h"
#include "hdr.h"

static __always_inline int add_blake3_pot_tlv(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *end = (void *)(long)skb->data_end;

    struct ethhdr *eth = ETH_HDR_PTR;
    struct ipv6hdr *ipv6 = IPV6_HDR_PTR;
    struct srh *srh = SRH_HDR_PTR;

    __u64 len = skb->len;
    __u64 offset = tlv_hdr_offset(srh);

    if (inc_skb_hdr_len(skb, BLAKE3_POT_TLV_LEN) < 0)
        return -1;

#pragma clang loop unroll(full)
    for (__u32 i = 0; i < MAX_PAYLOAD_SHIFT_LEN; ++i) {
        if (i >= BLAKE3_POT_TLV_LEN + HDR_ADDING_OFFSET) break;

        __u64 tail_ptr = len - 1 - i;
        __u64 head_ptr = len - 1 - i + BLAKE3_POT_TLV_LEN;

        __u8 byte;
        if (bpf_skb_load_bytes(skb, tail_ptr, &byte, 1) < 0) return -1;
        if (bpf_skb_store_bytes(skb, head_ptr, &byte, 1, 0) < 0) return -1;
    }
#pragma clang loop unroll(full)
    for (__u32 i = 0; i < MAX_PAYLOAD_SHIFT_LEN; ++i) {
        if (i >= BLAKE3_POT_TLV_LEN) break;

        __u64 head_ptr = offset - 1 - i + BLAKE3_POT_TLV_LEN;
        __u64 tail_ptr = offset - 1 - i + BLAKE3_POT_TLV_LEN + BLAKE3_POT_TLV_LEN;

        __u8 byte;
        if (bpf_skb_load_bytes(skb, head_ptr, &byte, 1) < 0) return -1;
        if (bpf_skb_store_bytes(skb, tail_ptr, &byte, 1, 0) < 0) return -1;
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

    struct blake3_pot_tlv tlv;
    if (fill_tlv(&tlv) < 0) {
        bpf_printk("[seg6_pot_tlv][-] fill_tlv failed");
        return -1;
    }

    if (chain_keys(&tlv, srh, end) < 0)
        return -1;

    if ((void *)data + offset + BLAKE3_POT_TLV_LEN > end) {
        bpf_printk("[seg6_pot_tlv][-] not enough space in packet buffer for TLV");
        return -1;
    }

    if (bpf_skb_store_bytes(skb, tlv_hdr_offset(srh), &tlv, BLAKE3_POT_TLV_LEN, BPF_F_RECOMPUTE_CSUM) < 0) {
        bpf_printk("[seg6_pot_tlv][-] bpf_skb_store_bytes failed to write the new TLV");
        return -1;
    }

    if (recalc_skb_ip6_tlv_len(skb, BLAKE3_POT_TLV_LEN) < 0) {
        bpf_printk("[seg6_pot_tlv][-] recalc_skb_ip6_tlv_len failed");
        return -1;
    }

    if (recalc_skb_tlv_len(skb, BLAKE3_POT_TLV_EXT_LEN) < 0) {
        bpf_printk("[seg6_pot_tlv][-] recalc_skb_tlv_len failed");
        return -1;
    }

    return 0;
}

#endif /* __SEG6_TLV_ADD_H */