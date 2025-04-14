#ifndef __BLAKE3_POT_TLV_H
#define __BLAKE3_POT_TLV_H

#include <linux/bpf.h>
#include <linux/types.h>

#include <linux/in6.h>
#include <linux/icmpv6.h>

#include "crypto/blake3.h"
#include "srh.h"
#include "hdr.h"

/*
Define the custom TLV structure for proof-of-transit using BLAKE3.
  0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
|   Type (8b)   |  Length (8b)  |      Reserved/Flags (16b)      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
|                          Token (32b)                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
|                        Timestamp (64b)                         |
|                            ...                                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
|                        (BLAKE3 256b)                           |
|                            ...                                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
*/
struct blake3_pot_tlv {
    __u8 type;
    __u8 length;
    __u64 timestamp;
    __u32 token;
    __u16 reserved;
    __u8 data[32]; // 256-bit BLAKE3 digest
} __attribute__((packed));

/*
Total TLV length = 48 bytes.
 Bytes 0: TLV Type (TRANSIT_TLV_TYPE)
 Bytes 1: Payload Length (46 bytes = 14 transit + 32 digest)
 Bytes 2-9: Timestamp (8 bytes)
 Bytes 10-13: Token (4 bytes)
 Bytes 14-15: Reserved (2 bytes)
 Bytes 16-47: BLAKE3 digest (32 bytes)
*/
#define BLAKE3_POT_TLV_LEN sizeof(struct blake3_pot_tlv)
#define BLAKE3_POT_TLV_WR_LEN (BLAKE3_POT_TLV_LEN - 2) // 14 transit + 32 digest
#define BLAKE3_POT_TLV_EXT_LEN (BLAKE3_POT_TLV_LEN / 8)
#define BLAKE3_POT_TLV_TYPE 4 // Defines a new TLV type

#define MAX_PAYLOAD_SHIFT_LEN 512

static __always_inline int compute_blake3(struct blake3_pot_tlv *tlv)
{
    tlv->type = BLAKE3_POT_TLV_TYPE;
    tlv->length = BLAKE3_POT_TLV_WR_LEN;
    tlv->timestamp = bpf_ktime_get_ns();
    tlv->token = bpf_get_prandom_u32();
    tlv->reserved = 0;

    // TODO: Lookup for the node secret key
    blake3_hash((const __u8 *)&tlv->timestamp, sizeof(tlv->timestamp) + sizeof(tlv->token) + sizeof(tlv->reserved), tlv->data);

    if (BLAKE3_POT_TLV_LEN % 8 != 0) {
        bpf_printk("[seg6_pot_tlv] warning: TLV length %d not multiple of 8 for SRH update", BLAKE3_POT_TLV_LEN);
        return -1;
    }

    return 0;
}

static __always_inline int recalc_skb_ip6_tlv_len(struct __sk_buff *skb)
{
    // ! We really need to refresh skb data pointers before to rewrite them
    void *data = (void *)(long)skb->data;
    void *end = (void *)(long)skb->data_end;

    struct ipv6hdr *ipv6 = IPV6_HDR_PTR;
    if (ip6_hdr_cb(ipv6, end) < 0)
        return -1;

    inc_ip6_hdr_len(ipv6, BLAKE3_POT_TLV_LEN);
    return 0;
}

static __always_inline int recalc_skb_tlv_len(struct __sk_buff *skb)
{
    // ! We really need to refresh skb data pointers before to rewrite them
    void *data = (void *)(long)skb->data;
    void *end = (void *)(long)skb->data_end;

    struct srh *srh = SRH_HDR_PTR;
    if (srh_hdr_cb(srh, end) < 0)
        return -1;

    srh->hdr_ext_len += BLAKE3_POT_TLV_EXT_LEN;
    return 0;
}

static __always_inline int recalc_ctx_ip6_tlv_len(struct xdp_md *ctx)
{
    // ! We really need to refresh ctx data pointers before to rewrite them
    void *data = (void *)(long)ctx->data;
    void *end = (void *)(long)ctx->data_end;

    struct ipv6hdr *ipv6 = IPV6_HDR_PTR;
    if (ip6_hdr_cb(ipv6, end) < 0)
        return -1;

    dec_ip6_hdr_len(ipv6, BLAKE3_POT_TLV_LEN);
    return 0;
}

static __always_inline int recalc_ctx_tlv_len(struct xdp_md *ctx)
{
    // ! We really need to refresh ctx data pointers before to rewrite them
    void *data = (void *)(long)ctx->data;
    void *end = (void *)(long)ctx->data_end;

    struct srh *srh = SRH_HDR_PTR;
    if (srh_hdr_cb(srh, end) < 0)
        return -1;

    srh->hdr_ext_len -= BLAKE3_POT_TLV_EXT_LEN;
    return 0;
}

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

    if (compute_blake3(&tlv) < 0) {
        bpf_printk("[seg6_pot_tlv][-] compute_blake3 failed");
        return -1;
    }

    if ((void *)data + offset + BLAKE3_POT_TLV_LEN > end) {
        bpf_printk("[seg6_pot_tlv][-] not enough space in packet buffer for TLV");
        return -1;
    }

    if (bpf_skb_store_bytes(skb, tlv_hdr_offset(srh), &tlv, BLAKE3_POT_TLV_LEN, BPF_F_RECOMPUTE_CSUM) < 0) {
        bpf_printk("[seg6_pot_tlv][-] bpf_skb_store_bytes failed to write the new TLV");
        return -1;
    }

    if (recalc_skb_ip6_tlv_len(skb) < 0) {
        bpf_printk("[seg6_pot_tlv][-] recalc_skb_ip6_tlv_len failed");
        return -1;
    }

    if (recalc_skb_tlv_len(skb) < 0) {
        bpf_printk("[seg6_pot_tlv][-] recalc_skb_tlv_len failed");
        return -1;
    }

    return 0;
}

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

    if (recalc_ctx_ip6_tlv_len(ctx) < 0) {
        bpf_printk("[seg6_pot_tlv][-] recalc_ctx_ip6_tlv_len failed");
        return -1;
    }

    if (recalc_ctx_tlv_len(ctx) < 0) {
        bpf_printk("[seg6_pot_tlv][-] recalc_ctx_tlv_len failed");
        return -1;
    }

    return 0;
}

static __always_inline int update_blake3_pot_tlv(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *end = (void *)(long)skb->data_end;

    struct ethhdr *eth = ETH_HDR_PTR;
    struct ipv6hdr *ipv6 = IPV6_HDR_PTR;
    struct srh *srh = SRH_HDR_PTR;

    if ((void *)data + tlv_hdr_offset(srh) + BLAKE3_POT_TLV_LEN > end) {
        bpf_printk("[seg6_pot_tlv][-] not enough space in packet buffer for TLV");
        return -1;
    }

    // TODO: compute the new hash chaining with the past one
    struct blake3_pot_tlv *tlv = SRH_HDR_PTR + tlv_hdr_offset(srh);
    bpf_printk("[seg6_pot_tlv] PoT TLV BLAKE3 digest: %x", tlv->data);

    return 0;
}

#endif /* __BLAKE3_POT_TLV_H */