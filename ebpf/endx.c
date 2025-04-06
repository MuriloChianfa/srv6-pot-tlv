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
#include "include/srh.h"
#include "include/tlv.h"

SEC("xdp")
int seg6_endx_blake3_pot_tlv_validator(struct xdp_md *ctx)
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
            if (srh_check_boundaries(srh, data_end) < 0)
                return XDP_DROP;

            // TODO: check the blake3 pot tlv chain partial validity...
        
            bpf_printk("[End.X] Segment packet processed");
            return XDP_PASS;
        default:
            return XDP_PASS;
    }

    return XDP_PASS;
}

SEC("tc")
int seg6_endx_blake3_pot_tlv_incrementor(struct __sk_buff *skb)
{
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    struct ethhdr *eth = data;
    struct ipv6hdr *ipv6 = (struct ipv6hdr *)(eth + 1);

    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    if (eth->h_proto != bpf_htons(ETH_P_IPV6))
        return TC_ACT_OK;

    if ((void *)(ipv6 + 1) > data_end)
        return TC_ACT_OK;

    struct blake3_pot_tlv *blake3_pot_tlv = {0};

    switch (ipv6->nexthdr) {
        case SRH_NEXT_HEADER:
            if (add_tlv(skb, data, data_end, blake3_pot_tlv) < 0)
                return TC_ACT_SHOT;
            
            // TODO: calculate and update the blake3 pot tlv chain for proof-of-transit of current segment...
        
            bpf_printk("[End.DT6] First-Segment packet processed");
        default:
            return TC_ACT_OK;
    }

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
