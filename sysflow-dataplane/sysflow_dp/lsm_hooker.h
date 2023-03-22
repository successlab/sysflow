#include <linux/kernel.h>
#include <linux/slab.h>

#include <linux/sysflow.h>
#include <linux/sysflow_event.h>
#include <linux/protocol.h>

struct datapath {
    //  struct rcu_head rcu;
    // struct list_head list_node;

    /* Flow table. */
    struct sysflow_table *table;
};

extern struct datapath *gDp;

extern inline int s2os_invoke_sysflow_func(void* pData, void* retData);