#ifndef FLOW_H
#define FLOW_H 1

//#include <linux/cache.h>
#include <linux/kernel.h>
#include <linux/types.h>
//#include <linux/time.h>

//#include "event.h"

/*
#define SYSFLOW_ACTION_UNKOWN	 	-1
#define SYSFLOW_ACTION_ALLOW	 	0
#define SYSFLOW_ACTION_DENY		 	1
#define SYSFLOW_ACTION_REDIRECT  	2
#define SYSFLOW_ACTION_QRAUNTINE 	3
#define SYSFLOW_ACTION_TAG		 	4
#define SYSFLOW_ACTTION_ISOLATION 	5
#define SYSFLOW_ACTION_MIGRATION	6
#define SYSFLOW_ACTION_LOG 			7
#define SYSFLOW_ACTION_ALERT 		8
#define SYSFLOW_ACTION_MESSAGE		9
*/

/*
struct file_id {
	//u128	uuid;
	uint32_t uuid[4];
	//u32 inode_num;
	uint32_t inode_num;
};
*/

struct sysflow_key {
	union{
		uint32_t pid;	//process id
	};

	union{
		struct file_id fid;
	};

	uint32_t opcode;  //sysflow operation ID for system events
};



struct sysflow_key_range {
	unsigned short int start;
	unsigned short int end;
};

struct sysflow_mask {
//	int ref_count;
//	struct rcu_head rcu;
//	struct swflow_key_range range;
//	struct swflow_key key;
};


struct sysflow_match {
	struct sysflow_key *key;
	struct sysflow_key_range range;
	struct sysflow_mask *mask;
};

struct sysflow_action{
	int action_type;
	int len;
	char* action_code;	//parameters for sysflow action if necessary
};


/*
//entry of flow table
struct sysflow_entry {
	struct rcu_head rcu;
	struct {
		struct hlist_node node[2];
		u32 hash;
	} flow_table, ufid_table;
	int stats_last_writer;		// NUMA-node id of the last writer on * 'stats[0]'.
	
	struct sysflow_key key;
	struct sysflow_id id;
	struct sysflow_mask *mask;
	struct sysflow_actions __rcu *sf_acts;

	//TODO: supporting metadata
	//struct flow_stats __rcu *stats[];  One for each NUMA node.  First one
					   //is allocated at flow creation time,
					   //the rest are allocated on demand
					   //while holding the 'stats[0].lock'.
					   //
};
*/
	
/****************flow table implementation*******************/
/*
//entry for exact match
struct exact_match_entry {	
	u32 hash;
	u32 mask_index;
};

struct mask_array {
	struct rcu_head rcu;
	int count, max;
	struct sw_flow_mask __rcu *masks[];
};

struct table_instance {
	struct flex_array *buckets;
	unsigned int n_buckets;
	struct rcu_head rcu;
	int node_ver;
	u32 hash_seed;
	bool keep_flows;
};

struct flow_table {
	struct table_instance __rcu *ti;
	struct table_instance __rcu *ufid_ti;
	struct mask_cache_entry __percpu *mask_cache;	//for exact match
	struct mask_array __rcu *mask_array;
	unsigned long last_rehash;
	unsigned int count;
	unsigned int ufid_count;
};
*/

/*
int sysflow_tbl_init(void);
void sysflow_tbl_exit(void);

int sysflow_tbl_insert(struct flow_table *table, struct swflow *flow,
			const struct swflow_mask *mask);
void sysflow_tbl_remove(struct flow_table *table, struct swflow *flow);


struct sysflow *sysflow_tbl_lookup_stats(struct flow_table *,
					  const struct sysflow_key *,
					  u32 skb_hash,
					  u32 *n_mask_hit);

struct sysflow *sysflow_tbl_lookup(struct flow_table *,
				    const struct sysflow_key *);

struct sysflow *sysflow_tbl_lookup_exact(struct flow_table *tbl,
					  const struct sysflow_match *match);

struct sysflow_action sysflow_received_event(struct sysflow_system_event* sse);
*/
#endif /* flow.h */


