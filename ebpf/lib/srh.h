#ifndef __SRH_H
#define __SRH_H

#include <linux/in6.h>
#include <linux/types.h>

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
							   ...
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

// SRv6 SRH help functions
int srh_get_hdr_len(struct srh *hdr);
int srh_check_boundaries(struct srh *hdr, void *end);

#endif /* __SRH_H */