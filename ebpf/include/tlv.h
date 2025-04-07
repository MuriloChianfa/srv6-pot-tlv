#ifndef __BLAKE3_POT_TLV_H
#define __BLAKE3_POT_TLV_H

#include <linux/types.h>
#include "blake3.h"
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

static __always_inline int compute_blake3(struct blake3_pot_tlv *tlv)
{
    tlv->type = BLAKE3_POT_TLV_TYPE;
    tlv->length = BLAKE3_POT_TLV_WR_LEN;
    tlv->timestamp = bpf_ktime_get_ns();
    tlv->token = bpf_get_prandom_u32();
    tlv->reserved = 0;

    blake3_hash((const __u8 *)&tlv->timestamp, sizeof(tlv->timestamp) + sizeof(tlv->token) + sizeof(tlv->reserved), tlv->data);

    if (BLAKE3_POT_TLV_LEN % 8 != 0) {
        bpf_printk("[snode] warning: TLV length %d not multiple of 8 for SRH update", BLAKE3_POT_TLV_LEN);
        return -1;
    }

    return 0;
}

static __always_inline int recalc_ip6_tlv_len(struct __sk_buff *skb)
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

static __always_inline int add_blake3_pot_tlv(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *end = (void *)(long)skb->data_end;

    struct ethhdr *eth = ETH_HDR_PTR;
    struct ipv6hdr *ipv6 = IPV6_HDR_PTR;
    struct srh *srh = SRH_HDR_PTR;

    struct blake3_pot_tlv tlv;
    compute_blake3(&tlv);

    if ((void *)data + tlv_hdr_offset(srh) + BLAKE3_POT_TLV_LEN > end) {
        bpf_printk("[snode][-] not enough space in packet buffer for TLV");
        return -1;
    }

    if (bpf_skb_store_bytes(skb, tlv_hdr_offset(srh), &tlv, BLAKE3_POT_TLV_LEN, 0) < 0) {
        bpf_printk("[snode][-] bpf_skb_store_bytes failed to write the new TLV");
        return -1;
    }

    recalc_ip6_tlv_len(skb);
    recalc_skb_tlv_len(skb);

    if (inc_skb_hdr_len(skb, BLAKE3_POT_TLV_LEN) < 0)
        return -1;

    return 0;
}

#endif /* __BLAKE3_POT_TLV_H */