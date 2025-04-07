#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/pkt_cls.h>
#include <linux/seg6.h>
#include <linux/types.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "include/blake3.h"
#include "include/hdr.h"
#include "include/srh.h"
#include "include/tlv.h"

SEC("xdp")
int seg6_dnode(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    struct ipv6hdr *ipv6 = (struct ipv6hdr *)(eth + 1);

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IPV6))
        return XDP_PASS;

    if ((void *)(ipv6 + 1) > data_end)
        return XDP_PASS;

    struct srh *srh = (struct srh *)(ipv6 + 1);

    switch (ipv6->nexthdr) {
        case SRH_NEXT_HEADER:
            if (srh_hdr_cb(srh, data_end) < 0)
                return XDP_DROP;

            // TODO: check the blake3 pot tlv chain validity...
        
            bpf_printk("[dnode] Last-Segment packet processed");
            return XDP_PASS;
        default:
            return XDP_PASS;
    }

    return XDP_PASS;
}

SEC("tc")
int seg6_snode(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *end = (void *)(long)skb->data_end;

    struct ethhdr *eth = ETH_HDR_PTR;
    struct ipv6hdr *ipv6 = IPV6_HDR_PTR;

    if (eth_hdr_cb(eth, end) < 0)
        return TC_ACT_OK;

    if (eth->h_proto != bpf_htons(ETH_P_IPV6))
        return TC_ACT_OK;

    if (ip6_hdr_cb(ipv6, end) < 0)
        return TC_ACT_OK;

    switch (ipv6->nexthdr) {
        case SRH_NEXT_HEADER:
            struct srh *srh = SRH_HDR_PTR;

            if (srh_hdr_cb(srh, end) < 0)
                return TC_ACT_OK;

            if (seg6_first_sid(srh) < 0) {
                bpf_printk("[snode] Not the first segment, skipping TLV add");
                return TC_ACT_OK;
            }

            if (add_blake3_pot_tlv(skb) != 0) {
                bpf_printk("[snode] add_tlv failed");
                return TC_ACT_SHOT;
            }

            bpf_printk("[snode] TLV added successfully");
        default:
            return TC_ACT_OK;
    }

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
