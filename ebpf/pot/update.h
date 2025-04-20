#ifndef __SEG6_TLV_UPDATE_H
#define __SEG6_TLV_UPDATE_H

#include <linux/in6.h>
#include <linux/types.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "tlv.h"

static __always_inline int update_pot_tlv(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = ETH_HDR_PTR;
    struct srh *srh = SRH_HDR_PTR;

    if ((void *)data + tlv_hdr_offset(srh) + POT_TLV_WIRE_LEN > end) {
        bpf_printk("[seg6_pot_tlv][-] not enough space in packet buffer for TLV");
        return -1;
    }

    struct pot_tlv *tlv = SRH_HDR_PTR + srh_hdr_len(srh);

    if (SRH_HDR_PTR + srh_hdr_len(srh) + POT_TLV_WIRE_LEN > end) {
        bpf_printk("[seg6_pot_tlv][-] invalid offset on packet buffer for TLV");
        return -1;
    }

    if (compute_witness_once(&tlv, srh, end) < 0) {
        bpf_printk("[seg6_pot_tlv][-] compute_witness failed");
        return -1;
    }

    // TODO: rewrite the updated witness into the packet
    return 0;
}

#endif /* __SEG6_TLV_UPDATE_H */