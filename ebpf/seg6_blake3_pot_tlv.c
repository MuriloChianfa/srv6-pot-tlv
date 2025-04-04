#include <seg6_blake3_pot_tlv.h>

// Dummy BLAKE3 implementation (for demo purposes)
// We remove the conditional in the loop because we ensure the caller has verified
// that at least 64 bytes are readable.
static __always_inline void compute_blake3(const void *data, __u32 len, __u8 *out) {
    __u8 sum = 24;
    __u8 *ptr = (__u8 *)data;

    if (len > 64)
        len = 64;

    // Always iterate 64 times (caller must ensure data is accessible)
// #pragma unroll
//     for (__u32 i = 0; i < 16; i++) {
//         sum += ptr[i];
//     }

#pragma unroll
    for (int i = 0; i < 32; i++) {
        out[i] = sum; // Demo: fill digest with the same value.
    }
}

SEC("xdp")
int xdp_seg6_blake3_pot_tlv(struct xdp_md *ctx)
{
    /***************************************************************
     * 1. INITIAL PARSE (before tail adjust)
     ***************************************************************/
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    bpf_trace_printk("DEBUG: Enter XDP program\n", sizeof("DEBUG: Enter XDP program\n"));

    // Parse Ethernet
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        bpf_trace_printk("DEBUG: Eth header OOB\n", sizeof("DEBUG: Eth header OOB\n"));
        return XDP_PASS;
    }
    if (bpf_ntohs(eth->h_proto) != ETH_P_IPV6) {
        bpf_trace_printk("DEBUG: Not IPv6\n", sizeof("DEBUG: Not IPv6\n"));
        return XDP_PASS;
    }

    // Parse IPv6 header
    struct ipv6hdr *ip6h = (void *)(eth + 1);
    if ((void *)(ip6h + 1) > data_end) {
        bpf_trace_printk("DEBUG: IPv6 header OOB\n", sizeof("DEBUG: IPv6 header OOB\n"));
        return XDP_PASS;
    }

    // Check for SRH
    if (ip6h->nexthdr != SRH_NEXT_HEADER) {
        bpf_trace_printk("DEBUG: No SRH\n", sizeof("DEBUG: No SRH\n"));
        return XDP_PASS;
    }

    // SRH starts right after IPv6 header
    __u8 *srh_ptr = (__u8 *)(ip6h + 1);
    if (srh_ptr + 8 > (__u8 *)data_end) {
        bpf_trace_printk("DEBUG: SRH header OOB\n", sizeof("DEBUG: SRH header OOB\n"));
        return XDP_PASS;
    }

    // Calculate SRH total length
    __u8 srh_hdrlen = srh_ptr[1];
    __u16 srh_total_len = (srh_hdrlen + 1) << 3;
    if (srh_ptr + srh_total_len > (__u8 *)data_end) {
        bpf_trace_printk("DEBUG: Full SRH OOB\n", sizeof("DEBUG: Full SRH OOB\n"));
        return XDP_PASS;
    }

    // Check segments_left == 0 (our assumption for starting router)
    if (srh_ptr[3] != 0) {
        bpf_trace_printk("DEBUG: segments_left != 0\n", sizeof("DEBUG: segments_left != 0\n"));
        return XDP_PASS;
    }

    /***************************************************************
     * 2. TAIL ADJUST TO MAKE ROOM FOR TLV
     ***************************************************************/
    int ret = bpf_xdp_adjust_tail(ctx, TRANSIT_TLV_TOTAL_LEN);
    if (ret < 0) {
        bpf_trace_printk("DEBUG: Tail adjust failed\n", sizeof("DEBUG: Tail adjust failed\n"));
        return XDP_DROP;
    }

    /***************************************************************
     * 3. RE-PARSE AFTER TAIL ADJUST
     ***************************************************************/
    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;

    bpf_trace_printk("DEBUG: Tail adjusted, new data_end=%p\n",
                     sizeof("DEBUG: Tail adjusted, new data_end=%p\n"), data_end);

    // Re-parse Ethernet
    eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // Re-parse IPv6
    ip6h = (void *)(eth + 1);
    if ((void *)(ip6h + 1) > data_end)
        return XDP_PASS;

    // Re-locate SRH
    srh_ptr = (__u8 *)(ip6h + 1);
    // Make sure original SRH is still valid
    if (srh_ptr + srh_total_len > (__u8 *)data_end) {
        bpf_trace_printk("DEBUG: SRH OOB after tail adjust\n", sizeof("DEBUG: SRH OOB after tail adjust\n"));
        return XDP_DROP;
    }

    /***************************************************************
     * 4. COMPUTE HASH
     *    - We want at least 64 bytes from ip6h for dummy BLAKE3.
     ***************************************************************/
    __u8 *ip6_ptr = (__u8 *)ip6h;
    if (ip6_ptr + 64 > (unsigned char *)data_end) {
        bpf_trace_printk("DEBUG: Not enough bytes for hash\n", sizeof("DEBUG: Not enough bytes for hash\n"));
        return XDP_DROP;
    }

    // Compute BLAKE3 digest over IPv6 + SRH
    __u32 hash_input_len = sizeof(*ip6h) + srh_total_len;
    __u8 hash[32];
    compute_blake3(ip6h, hash_input_len, hash);
    bpf_trace_printk("DEBUG: Digest computed, first byte: %d\n",
                     sizeof("DEBUG: Digest computed, first byte: %d\n"), hash[0]);

    /***************************************************************
     * 5. WRITE THE NEW TLV
     ***************************************************************/
    // The TLV will follow immediately after the original SRH
    __u8 *tlv = srh_ptr + srh_total_len;

    // Check we have room for the 48-byte TLV
    if (tlv + TRANSIT_TLV_TOTAL_LEN > (unsigned char *)data_end) {
        bpf_trace_printk("DEBUG: TLV placement OOB\n", sizeof("DEBUG: TLV placement OOB\n"));
        return XDP_DROP;
    }

    // Write Type and Length
    tlv[0] = TRANSIT_TLV_TYPE;  // e.g. 0xFE
    tlv[1] = TRANSIT_TLV_PAYLOAD_LEN;  // 46

    // Timestamp (8 bytes, big-endian)
    __u64 timestamp = bpf_ktime_get_ns();
    __u64 ts_net = __builtin_bswap64(timestamp);
#pragma unroll
    for (int i = 0; i < 8; i++) {
        tlv[2 + i] = ((__u8 *)&ts_net)[i];
    }

    // Token (4 bytes, big-endian)
    __u32 token = bpf_get_prandom_u32();
    __u32 token_net = __builtin_bswap32(token);
#pragma unroll
    for (int i = 0; i < 4; i++) {
        tlv[10 + i] = ((__u8 *)&token_net)[i];
    }

//     // Reserved (2 bytes, big-endian 0)
//     __u16 reserved = 0;
//     __u16 reserved_net = __builtin_bswap16(reserved);
// #pragma unroll
//     for (int i = 0; i < 2; i++) {
//         tlv[14 + i] = ((__u8 *)&reserved_net)[i];
//     }

//     // BLAKE3 digest (32 bytes)
// #pragma unroll
//     for (int i = 0; i < 32; i++) {
//         tlv[16 + i] = hash[i];
//     }

    /***************************************************************
     * 6. INCREASE SRH hdrlen (by 6, for 48 bytes => 6 * 8 = 48)
     ***************************************************************/
    srh_ptr[1] = srh_hdrlen + 6;

    bpf_trace_printk("DEBUG: TLV appended successfully\n",
                     sizeof("DEBUG: TLV appended successfully\n"));
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";