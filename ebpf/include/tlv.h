#ifndef __BLAKE3_POT_TLV_H
#define __BLAKE3_POT_TLV_H

#include <linux/types.h>
#include "blake3.h"
#include "srh.h"

/*
Define the custom TLV structure for proof-of-transit using BLAKE3.
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-----------------------------------------------------------------+
|      Type      |    Length     |      Reserved/Flags (16 bits)  |
+-----------------------------------------------------------------+
|                         (BLAKE3 Hashs)                          |
+-----------------------------------------------------------------+
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
#define BLAKE3_POT_TLV_TYPE 4 // Defines a new TLV type

static __always_inline int add_tlv(struct __sk_buff *skb, void *data, void *data_end, struct blake3_pot_tlv *tlv)
{
    if (data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr) > data_end)
        return -1;

    struct ipv6hdr *ipv6 = data + sizeof(struct ethhdr);
    struct ipv6_sr_hdr *srh = data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr);

    ipv6->payload_len = bpf_htons(bpf_ntohs(ipv6->payload_len) + sizeof(struct srh) + BLAKE3_POT_TLV_LEN);
	ipv6->nexthdr = SRH_NEXT_HEADER;

    bpf_skb_adjust_room(skb, BLAKE3_POT_TLV_LEN + 8, BPF_ADJ_ROOM_NET, 0);

    tlv->type = BLAKE3_POT_TLV_TYPE;
    tlv->length = 46;
    tlv->timestamp = bpf_ktime_get_ns();
    tlv->token = bpf_get_prandom_u32();
    tlv->reserved = 0;

    blake3_hash((const __u8 *)&tlv->timestamp, 14, tlv->data);

    __u32 offset = sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + sizeof(struct srh);
    if (bpf_skb_store_bytes(skb, (unsigned long)offset, tlv, BLAKE3_POT_TLV_LEN, 0) < 0)
        return -1;

    srh->hdrlen += BLAKE3_POT_TLV_LEN / 8;
    srh->nexthdr = SRH_NEXT_HEADER;

    return 0;
}

#endif /* __BLAKE3_POT_TLV_H */