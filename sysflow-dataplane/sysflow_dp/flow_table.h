#include <linux/jhash.h>
#include <linux/slab.h>
#include <linux/flex_array.h>
#include <linux/random.h>
#include <linux/rculist.h>
#include <linux/list.h>

#include "linux/sysflow.h"

#define MASK_ARRAY_SIZE_MIN 100
#define TBL_MIN_BUCKETS		256
#define SFPFM_MAX_NAME  256

#define _DBG 0

struct datapath {
    //  struct rcu_head rcu;
    // struct list_head list_node;

    /* Flow table. */
    struct sysflow_table *table;
};