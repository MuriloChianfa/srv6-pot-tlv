#ifndef __SEG6_SRH_H
#define __SEG6_SRH_H

#include <linux/in6.h>
#include <linux/types.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "hdr.h"

#define HDR_EXT_LEN 0 // HDR Routing header extenstion length
#define SRH_NEXT_HEADER 43 // SRH next header value per RFC 8754
#define SRH_ROUTING_HEADER_TYPE 4 // SRv6 Routing type flag

/*
            RFC 8754 - IPv6 Segment Routing Header (SRH)
  0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 | Next Header   |  Hdr Ext Len  | Routing Type  | Segments Left |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |  Last Entry   |     Flags     |              Tag              |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                                                               |
 |            Segment List[0] (128-bit IPv6 address)             |
 |                                                               |
 |                                                               |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                                                               |
 |                                                               |
 |                             ...                               |
 |                                                               |
 |                                                               |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                                                               |
 |            Segment List[n] (128-bit IPv6 address)             |
 |                                                               |
 |                                                               |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 //                                                             //
 //         Optional Type Length Value objects (variable)       //
 //                                                             //
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
struct srh {
    __u8 next_hdr;
    __u8 hdr_ext_len;
    __u8 routing_type;
    __u8 segments_left;
    __u8 last_entry;
    __u8 flags;
    __u16 tag;
    struct in6_addr segments[0];
} __attribute__((packed));

static __always_inline int srh_hdr_len(struct srh *srh)
{
    return (srh->hdr_ext_len + 1) * 8;
}

static __always_inline int seg6_first_sid(struct srh *srh)
{
    if (srh->segments_left != srh->last_entry)
        return -1;
    return 0;
}

static __always_inline int srh_hdr_cb(struct srh *srh, void *end)
{
    if ((void *)srh + SRH_FIXED_HDR_LEN > end || (void *)srh + srh_hdr_len(srh) > end)
        return -1;
    return 0;
}

static __always_inline int tlv_hdr_offset(struct srh *srh)
{
    return ETH_HDR_LEN + IPV6_HDR_LEN + srh_hdr_len(srh);
}

#endif /* __SEG6_SRH_H */