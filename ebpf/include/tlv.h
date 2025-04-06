#ifndef __BLAKE3_POT_TLV_H
#define __BLAKE3_POT_TLV_H

#include <linux/types.h>

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
#define BLAKE3_POT_TLV_LEN offsetof(struct blake3_pot_tlv)
#define BLAKE3_POT_TLV_TYPE 0xFE

static __always_inline int add_tlv(struct __sk_buff *skb, void *data, void *data_end, struct blake3_pot_tlv *tlv)
{
    struct ipv6hdr *ipv6 = data + sizeof(struct ethhdr);

    if (data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr) > data_end)
        return -1;

    // TODO: write new tlv into srh...

    return 0;
}

#endif /* __BLAKE3_POT_TLV_H */