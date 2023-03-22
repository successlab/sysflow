#ifndef SYSFLOW_LOADABLE_H
#define SYSFLOW_LOADABLE_H 1

struct datapath {
  //  struct rcu_head rcu;
   // struct list_head list_node;

    /* Flow table. */
    struct sysflow_table *table;

};

/*definitions for generic netlink*/
#define SYSFLOW_FLOW_FAMILY "sysflow_flow"
#define SYSFLOW_VERSION 0x1 

/*RCU defintions*/
#define sf_rcu_update_dereference(p)					\
	rcu_dereference_protected(p, 1)
#define sf_rcu_read_dereference(p)					\
	rcu_dereference_check(p, 1)

#endif /*sysflow_loadable.h*/