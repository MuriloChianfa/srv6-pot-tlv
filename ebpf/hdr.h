#ifndef __SEG6_HDR_H
#define __SEG6_HDR_H

#include <linux/in6.h>
#include <linux/types.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define IPV6_LEN sizeof(struct in6_addr) // IPv6 length
#define ETH_HDR_LEN sizeof(struct ethhdr) // L2 header length
#define IPV6_HDR_LEN sizeof(struct ipv6hdr) // IPv6 header length
#define SRH_FIXED_HDR_LEN sizeof(struct srh) // SRv6 minimal header length

#define HDR_BYTE_SIZE 8
#define MAX_PAYLOAD_SHIFT_LEN 512

#define ETH_HDR_OFFSET 0
#define HDR_ADDING_OFFSET HDR_BYTE_SIZE
#define IPV6_HDR_OFFSET ETH_HDR_LEN
#define SRH_HDR_OFFSET ETH_HDR_LEN + IPV6_HDR_LEN
#define TLV_MNML_HDR_OFFSET SRH_HDR_OFFSET + SRH_FIXED_HDR_LEN

#define ETH_HDR_PTR data
#define IPV6_HDR_PTR data + IPV6_HDR_OFFSET
#define SRH_HDR_PTR data + SRH_HDR_OFFSET

static __always_inline int eth_hdr_cb(struct ethhdr *eth, void *end)
{
    if ((void *)eth + ETH_HDR_LEN > end)
        return -1;
    return 0;
}

static __always_inline int ip6_hdr_cb(struct ipv6hdr *ip6, void *end)
{
    if ((void *)ip6 + IPV6_HDR_LEN > end)
        return -1;
    return 0;
}

static __always_inline void inc_ip6_hdr_len(struct ipv6hdr *ip6, __u32 len)
{
    ip6->payload_len = bpf_htons(bpf_ntohs(ip6->payload_len) + len);
}

static __always_inline void dec_ip6_hdr_len(struct ipv6hdr *ip6, __u32 len)
{
    ip6->payload_len = bpf_htons(bpf_ntohs(ip6->payload_len) - len);
}

static __always_inline int inc_skb_hdr_len(struct __sk_buff *skb, __u32 len)
{
    if (bpf_skb_change_tail(skb, skb->len + len, 0) < 0)
        return -1;
    return 0;
}

static __always_inline int dec_skb_hdr_len(struct xdp_md *ctx, __u32 len)
{
    if (bpf_xdp_adjust_tail(ctx, -len) < 0)
        return -1;
    return 0;
}

#endif /* __SEG6_HDR_H */