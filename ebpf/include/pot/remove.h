#ifndef __SEG6_TLV_REMOVE_H
#define __SEG6_TLV_REMOVE_H

#include <linux/in6.h>
#include <linux/types.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "tlv.h"
#include "hdr.h"

static __always_inline int remove_blake3_pot_tlv(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *end = (void *)(long)ctx->data_end;

    __u32 xdp_len = end - data;

    struct ethhdr *eth = ETH_HDR_PTR;
    struct ipv6hdr *ipv6 = IPV6_HDR_PTR;
    struct srh *srh = SRH_HDR_PTR;

    __u32 offset = tlv_hdr_offset(srh) - BLAKE3_POT_TLV_LEN;

    if (data + offset + BLAKE3_POT_TLV_LEN > end) {
        bpf_printk("[seg6_pot_tlv][-] packet too short to remove TLV?");
        return -1;
    }

    if (offset >= xdp_len) {
        bpf_printk("[seg6_pot_tlv][-] Invalid offset to remove TLV");
        return -1;
    }

#pragma unroll
    for (__u32 i = 0; i < MAX_PAYLOAD_SHIFT_LEN; ++i) {
        if (i >= xdp_len - (offset + BLAKE3_POT_TLV_LEN)) break;

        void *head_ptr = data + offset + i + BLAKE3_POT_TLV_LEN;
        void *tail_ptr = data + offset + i;

        if (head_ptr + 1 > end || tail_ptr + 1 > end) {
            bpf_printk("[seg6_pot_tlv][-] Shift bounds error i=%u", i);
            return -1;
        }

        *(volatile __u8 *)tail_ptr = *(volatile __u8 *)head_ptr;
    }

    if (dec_skb_hdr_len(ctx, (__u32)BLAKE3_POT_TLV_LEN) < 0) {
        bpf_printk("[seg6_pot_tlv][-] bpf_xdp_adjust_tail failed");
        return -1;
    }

    if (recalc_ctx_ip6_tlv_len(ctx, BLAKE3_POT_TLV_LEN) < 0) {
        bpf_printk("[seg6_pot_tlv][-] recalc_ctx_ip6_tlv_len failed");
        return -1;
    }

    if (recalc_ctx_tlv_len(ctx, BLAKE3_POT_TLV_EXT_LEN) < 0) {
        bpf_printk("[seg6_pot_tlv][-] recalc_ctx_tlv_len failed");
        return -1;
    }

    return 0;
}

#endif /* __SEG6_TLV_REMOVE_H */