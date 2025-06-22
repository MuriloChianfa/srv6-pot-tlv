#ifndef __SEG6_TLV_REMOVE_H
#define __SEG6_TLV_REMOVE_H

#include <linux/in6.h>
#include <linux/types.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "tlv.h"
#include "hdr.h"

static __always_inline int remove_pot_tlv(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *end = (void *)(long)ctx->data_end;

    __u32 xdp_len = (__u32)(end - data);
    struct srh *srh = SRH_HDR_PTR;

    if (recalc_ctx_tlv_len(ctx, POT_TLV_EXT_LEN) < 0) {
        bpf_printk("[seg6_pot_tlv][-] recalc_ctx_tlv_len failed");
        return -1;
    }

    struct pot_tlv *tlv = SRH_HDR_PTR + srh_hdr_len(srh);

    if (SRH_HDR_PTR + srh_hdr_len(srh) + POT_TLV_WIRE_LEN > end) {
        bpf_printk("[seg6_pot_tlv][-] invalid offset on packet buffer for TLV");
        return -1;
    }

    if (compute_witness_once(tlv, srh, end) < 0) {
        bpf_printk("[seg6_pot_tlv][-] compute_witness failed");
        return -1;
    }

    struct pot_tlv recursive_tlv;
    dup_tlv_nonce(tlv, &recursive_tlv);

    bpf_printk("[seg6_pot_tlv][*] Recursive recalculation of PoT digest");
    if (chain_keys(&recursive_tlv, srh, end) < 0) {
        bpf_printk("[seg6_pot_tlv][-] chain_keys failed");
        return -1;
    }

    bpf_printk("[seg6_pot_tlv][*] Comparing TLV digests");
    if (compare_pot_digest(tlv, &recursive_tlv) != 0) {
        bpf_printk("[seg6_pot_tlv][-] PoT TLV wrong, possible path mismatch!");
        return -1;
    }

    bpf_printk("[seg6_pot_tlv][*] TLV successfully validated");

    __u32 segment_size = calc_segment_size(srh, end);
    if (segment_size == 0) return -1;

    __u32 tlv_offset = SRH_HDR_OFFSET + SRH_FIXED_HDR_LEN + (IPV6_LEN * (__u32)segment_size);
    if (data + tlv_offset + POT_TLV_WIRE_LEN > end) {
        bpf_printk("[seg6_pot_tlv][-] packet too short to remove TLV?");
        return -1;
    }

    if (tlv_offset >= xdp_len) {
        bpf_printk("[seg6_pot_tlv][-] Invalid offset to remove TLV");
        return -1;
    }

    __u32 max_shift = xdp_len - (tlv_offset + POT_TLV_WIRE_LEN);
    if (max_shift > MAX_PAYLOAD_SHIFT_LEN)
        max_shift = MAX_PAYLOAD_SHIFT_LEN;

#pragma clang loop unroll(disable)
    for (__u32 i = 0; i < max_shift; ++i) {
        void *tail_ptr = data + tlv_offset + i;
        void *head_ptr = tail_ptr + POT_TLV_WIRE_LEN;

        if (head_ptr + 1 > end) {
            bpf_printk("[seg6_pot_tlv][-] Shift bounds error i=%u", i);
            break;
        }

        *(volatile __u8 *)tail_ptr = *(volatile __u8 *)head_ptr;
    }

    if (dec_skb_hdr_len(ctx, (__u32)POT_TLV_WIRE_LEN) < 0) {
        bpf_printk("[seg6_pot_tlv][-] bpf_xdp_adjust_tail failed");
        return -1;
    }

    if (recalc_ctx_ip6_tlv_len(ctx, POT_TLV_WIRE_LEN) < 0) {
        bpf_printk("[seg6_pot_tlv][-] recalc_ctx_ip6_tlv_len failed");
        return -1;
    }

    return 0;
}

#endif /* __SEG6_TLV_REMOVE_H */