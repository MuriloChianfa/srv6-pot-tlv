#ifndef __SEG6_TLV_UPDATE_H
#define __SEG6_TLV_UPDATE_H

#include <linux/in6.h>
#include <linux/types.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "hdr.h"
#include "tlv.h"

static __always_inline int update_pot_tlv(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *end = (void *)(long)ctx->data_end;

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

    if (reverse_recalc_ctx_tlv_len(ctx, POT_TLV_EXT_LEN) < 0) {
        bpf_printk("[seg6_pot_tlv][-] reverse_recalc_ctx_tlv_len failed");
        return -1;
    }

    return 0;
}

#endif /* __SEG6_TLV_UPDATE_H */