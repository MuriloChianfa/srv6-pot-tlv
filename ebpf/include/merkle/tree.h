#ifndef __SEG6_MERKLE_TREE_H
#define __SEG6_MERKLE_TREE_H

#include <linux/types.h>

#define MERKLE_NEXT_IDX (1 << 0)
#define MERKLE_ROOT_IDX MERKLE_NEXT_IDX
#define MERKLE_PARENT_IDX_OFFSET (1 << 1)

#endif /* __SEG6_MERKLE_TREE_H */