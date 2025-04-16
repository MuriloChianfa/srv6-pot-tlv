#ifndef __SEG6_TLV_UPDATE_H
#define __SEG6_TLV_UPDATE_H

#include <linux/in6.h>
#include <linux/types.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "tlv.h"

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

#endif /* __SEG6_TLV_UPDATE_H */