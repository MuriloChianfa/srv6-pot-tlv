#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ipv6.h>

#include <srh.h>

static __always_inline int add_tlv(struct __sk_buff *skb, void *data, void *data_end, struct blake3_pot_tlv *tlv)
{
    struct ipv6hdr *ipv6 = data + sizeof(struct ethhdr);

    if (data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr) > data_end)
        return -1;

    // TODO: write new tlv into srh...

    return 0;
}
