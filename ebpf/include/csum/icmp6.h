#ifndef __SEG6_ICMP_H
#define __SEG6_ICMP_H

#include <linux/types.h>

#define ICMPV6_PACKET_MAX_SAMPLE_SIZE 1280 - sizeof(struct ipv6hdr) - sizeof(struct icmp6hdr)

struct ipv6_pseudo_header_t {
    union {
        struct header {
            struct in6_addr src_ip;
            struct in6_addr dst_ip;
            __be32 top_level_length;
            __u8 zero[3];
            __u8 next_header;
        } __attribute__((packed)) fields;
        __u16 words[20];
    };
};

#ifndef csum_fold
static __always_inline __sum16 csum_fold(__wsum csum) {
    csum = (csum & 0xffff) + (csum >> 16);
    csum = (csum & 0xffff) + (csum >> 16);
    return (__sum16)~csum;
}
#endif

#ifndef csum_add
static __always_inline __wsum csum_add(__wsum csum, __wsum addend) {
    csum += addend;
    return csum + (csum < addend);
}
#endif

/* https://github.com/cilium/cilium/blob/103077d3ecf826b9329a02f7c0c0db8190452fe7/bpf/lib/lb.h#L2058 */
static __always_inline __wsum icmp_wsum_accumulate(void *data_start, void *data_end, int sample_len) {
    __wsum wsum = 0;

    #define body(i) if ((i) > sample_len) \
        return wsum; \
    if (data_start + (i) + sizeof(__u16) > data_end) { \
        if (data_start + (i) + sizeof(__u8) <= data_end) \
            wsum += *(__u8 *)(data_start + (i)); \
        return wsum; \
    } \
    wsum += *(__u16 *)(data_start + (i));

    #define body4(i) body(i) \
        body(i + 2) \
        body(i + 4) \
        body(i + 6)

    #define body16(i) body4(i) \
        body4(i + 8) \
        body4(i + 16) \
        body4(i + 24)

    #define body128(i) body16(i) \
        body16(i + 32) \
        body16(i + 64) \
        body16(i + 96)

    body128(0)
    body128(256)
    body128(512)
    body128(768)
    body128(1024)

    return wsum;
}

/* Memory iterators used below. */
#define __it_bwd(x, op) (x -= sizeof(__u##op))
#define __it_fwd(x, op) (x += sizeof(__u##op))

/* Memory operators used below. */
#define __it_set(a, op) (*(__u##op *)__it_bwd(a, op)) = 0
#define __it_xor(a, b, r, op) r |= (*(__u##op *)__it_bwd(a, op)) ^ (*(__u##op *)__it_bwd(b, op))
#define __it_mob(a, b, op) (*(__u##op *)__it_bwd(a, op)) = (*(__u##op *)__it_bwd(b, op))
#define __it_mof(a, b, op) \
    do { \
        *(__u##op *)a = *(__u##op *)b; \
        __it_fwd(a, op); __it_fwd(b, op); \
    } while (0)

static __always_inline void __bpf_memzero(void *d, __u64 len)
{
    if (!__builtin_constant_p(len))
        __builtin_trap();

    d += len;

    if (len > 1 && len % 2 == 1) {
        __it_set(d, 8);
        len -= 1;
    }

    switch (len) {
    case 96:         __it_set(d, 64); __attribute__((fallthrough));
    case 88: jmp_88: __it_set(d, 64); __attribute__((fallthrough));
    case 80: jmp_80: __it_set(d, 64); __attribute__((fallthrough));
    case 72: jmp_72: __it_set(d, 64); __attribute__((fallthrough));
    case 64: jmp_64: __it_set(d, 64); __attribute__((fallthrough));
    case 56: jmp_56: __it_set(d, 64); __attribute__((fallthrough));
    case 48: jmp_48: __it_set(d, 64); __attribute__((fallthrough));
    case 40: jmp_40: __it_set(d, 64); __attribute__((fallthrough));
    case 32: jmp_32: __it_set(d, 64); __attribute__((fallthrough));
    case 24: jmp_24: __it_set(d, 64); __attribute__((fallthrough));
    case 16: jmp_16: __it_set(d, 64); __attribute__((fallthrough));
    case  8: jmp_8:  __it_set(d, 64);
        break;

    case 94: __it_set(d, 16); __it_set(d, 32); goto jmp_88;
    case 86: __it_set(d, 16); __it_set(d, 32); goto jmp_80;
    case 78: __it_set(d, 16); __it_set(d, 32); goto jmp_72;
    case 70: __it_set(d, 16); __it_set(d, 32); goto jmp_64;
    case 62: __it_set(d, 16); __it_set(d, 32); goto jmp_56;
    case 54: __it_set(d, 16); __it_set(d, 32); goto jmp_48;
    case 46: __it_set(d, 16); __it_set(d, 32); goto jmp_40;
    case 38: __it_set(d, 16); __it_set(d, 32); goto jmp_32;
    case 30: __it_set(d, 16); __it_set(d, 32); goto jmp_24;
    case 22: __it_set(d, 16); __it_set(d, 32); goto jmp_16;
    case 14: __it_set(d, 16); __it_set(d, 32); goto jmp_8;
    case  6: __it_set(d, 16); __it_set(d, 32);
        break;

    case 92: __it_set(d, 32); goto jmp_88;
    case 84: __it_set(d, 32); goto jmp_80;
    case 76: __it_set(d, 32); goto jmp_72;
    case 68: __it_set(d, 32); goto jmp_64;
    case 60: __it_set(d, 32); goto jmp_56;
    case 52: __it_set(d, 32); goto jmp_48;
    case 44: __it_set(d, 32); goto jmp_40;
    case 36: __it_set(d, 32); goto jmp_32;
    case 28: __it_set(d, 32); goto jmp_24;
    case 20: __it_set(d, 32); goto jmp_16;
    case 12: __it_set(d, 32); goto jmp_8;
    case  4: __it_set(d, 32);
        break;

    case 90: __it_set(d, 16); goto jmp_88;
    case 82: __it_set(d, 16); goto jmp_80;
    case 74: __it_set(d, 16); goto jmp_72;
    case 66: __it_set(d, 16); goto jmp_64;
    case 58: __it_set(d, 16); goto jmp_56;
    case 50: __it_set(d, 16); goto jmp_48;
    case 42: __it_set(d, 16); goto jmp_40;
    case 34: __it_set(d, 16); goto jmp_32;
    case 26: __it_set(d, 16); goto jmp_24;
    case 18: __it_set(d, 16); goto jmp_16;
    case 10: __it_set(d, 16); goto jmp_8;
    case  2: __it_set(d, 16);
        break;

    case  1: __it_set(d, 8);
        break;

    default:
        __builtin_trap();
    }
}

#endif /* __SEG6_ICMP_H */