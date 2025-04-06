#ifndef __BLAKE3_H
#define __BLAKE3_H

#include <linux/types.h>

#define ROTR32(x, r) (((x) >> (r)) | ((x) << (32 - (r))))

/* BLAKE3 IV constants */
static const __u32 BLAKE3_IV[8] = {
    0x6A09E667u, 0xBB67AE85u, 0x3C6EF372u, 0xA54FF53Au,
    0x510E527Fu, 0x9B05688Cu, 0x1F83D9ABu, 0x5BE0CD19u
};

void gfunction(__u32 v[16], int a, int b, int c, int d, __u32 x, __u32 y);
void blake3_hash(const __u8 *msg, __u32 msg_len, __u8 out[32]);

#endif /* __BLAKE3_H */