#ifndef __SEG6_EXP_H
#define __SEG6_EXP_H

#include <linux/in6.h>
#include <linux/types.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "hdr.h"

static __always_inline int recalc_skb_ip6_tlv_len(struct __sk_buff *skb, __u16 len)
{
    void *data = (void *)(long)skb->data;
    void *end = (void *)(long)skb->data_end;

    struct ipv6hdr *ipv6 = IPV6_HDR_PTR;
    if (ip6_hdr_cb(ipv6, end) < 0)
        return -1;

    inc_ip6_hdr_len(ipv6, len);
    return 0;
}

static __always_inline int recalc_skb_tlv_len(struct __sk_buff *skb, __u16 len)
{
    void *data = (void *)(long)skb->data;
    void *end = (void *)(long)skb->data_end;

    struct srh *srh = SRH_HDR_PTR;
    if (srh_hdr_cb(srh, end) < 0)
        return -1;

    srh->hdr_ext_len += len;
    return 0;
}

static __always_inline int recalc_ctx_ip6_tlv_len(struct xdp_md *ctx, __u16 len)
{
    void *data = (void *)(long)ctx->data;
    void *end = (void *)(long)ctx->data_end;

    struct ipv6hdr *ipv6 = IPV6_HDR_PTR;
    if (ip6_hdr_cb(ipv6, end) < 0)
        return -1;

    dec_ip6_hdr_len(ipv6, len);
    return 0;
}

static __always_inline int recalc_ctx_tlv_len(struct xdp_md *ctx, __u16 len)
{
    void *data = (void *)(long)ctx->data;
    void *end = (void *)(long)ctx->data_end;

    struct srh *srh = SRH_HDR_PTR;
    if (srh_hdr_cb(srh, end) < 0)
        return -1;

    srh->hdr_ext_len -= len;
    return 0;
}

static __always_inline int reverse_recalc_ctx_tlv_len(struct xdp_md *ctx, __u16 len)
{
    void *data = (void *)(long)ctx->data;
    void *end = (void *)(long)ctx->data_end;

    struct srh *srh = SRH_HDR_PTR;
    if (srh_hdr_cb(srh, end) < 0)
        return -1;

    srh->hdr_ext_len += len;
    return 0;
}

#endif /* __SEG6_EXP_H */