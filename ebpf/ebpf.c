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

#include "crypto/blake3.h"
#include "hdr.h"
#include "srh.h"

#include "pot/add.h"
#include "pot/remove.h"
#include "pot/update.h"

SEC("xdp")
int seg6_pot_tlv_d(struct xdp_md *ctx)
{
    void *end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = ETH_HDR_PTR;
    struct ipv6hdr *ipv6;
    struct srh *srh;

    if (eth_hdr_cb(eth, end) < 0)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IPV6))
        return XDP_PASS;

    ipv6 = IPV6_HDR_PTR;

    if (ip6_hdr_cb(ipv6, end) < 0)
        return XDP_PASS;

    switch (ipv6->nexthdr) {
    case SRH_NEXT_HEADER:
        srh = SRH_HDR_PTR;

        if (srh_hdr_cb(srh, end) < 0)
            return XDP_PASS;

        // Endpoint Node
        if (seg6_last_sid(srh) == 0) {
            if (remove_pot_tlv(ctx) != 0) {
                bpf_printk("[seg6_pot_tlv][-] Failed to remove TLV\n");
                return XDP_DROP;
            }

            bpf_printk("[seg6_pot_tlv][+] TLV removed successfully\n");
            return XDP_PASS;
        }
        // Transit Nodes
        else {
            if (update_pot_tlv(ctx) != 0) {
                bpf_printk("[seg6_pot_tlv][-] Failed to update TLV\n");
                return XDP_DROP;
            }

            bpf_printk("[seg6_pot_tlv][+] TLV updated successfully\n");
        }
    default:
        return XDP_PASS;
    }

    return XDP_PASS;
}

SEC("tc")
int seg6_pot_tlv(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *end = (void *)(long)skb->data_end;

    struct ethhdr *eth = ETH_HDR_PTR;
    struct ipv6hdr *ipv6;
    struct srh *srh;

    if (eth_hdr_cb(eth, end) < 0)
        return TC_ACT_OK;

    if (eth->h_proto != bpf_htons(ETH_P_IPV6))
        return TC_ACT_OK;

    ipv6 = IPV6_HDR_PTR;

    if (ip6_hdr_cb(ipv6, end) < 0)
        return TC_ACT_OK;

    switch (ipv6->nexthdr) {
    case SRH_NEXT_HEADER:
        srh = SRH_HDR_PTR;

        if (srh_hdr_cb(srh, end) < 0)
            return TC_ACT_OK;

        // SRouting Node
        if (seg6_first_sid(srh) == 0) {
            if (add_pot_tlv(skb) != 0) {
                bpf_printk("[seg6_pot_tlv][-] Failed to add TLV\n");
                return TC_ACT_SHOT;
            }

            bpf_printk("[seg6_pot_tlv][+] TLV added successfully\n");
        }
    default:
        return TC_ACT_OK;
    }

    return TC_ACT_OK;
}

char _license[] SEC("license") = "Dual MIT/GPL";