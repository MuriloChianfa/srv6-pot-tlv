#include <srh.h>

static __always_inline int srh_get_hdr_len(struct srh *hdr)
{
    return (hdr->hdr_ext_len + 1) * 8;
}

static __always_inline int srh_check_boundaries(struct srh *hdr, void *end)
{
    if ((void *)hdr + sizeof(struct srh) > end || (void *)hdr + srh_get_hdr_len(hdr) > end)
        return -1;
    return 0;
}
