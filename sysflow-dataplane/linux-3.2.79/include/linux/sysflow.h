#ifndef SYSFLOW_H
#define SYSFLOW_H 1

#include <linux/cache.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/time.h>

#include "linux/sysflow_event.h"

#define SYSFLOW_ACTION_UNKNOWN	 	0
#define SYSFLOW_ACTION_ALLOW	 	1
#define SYSFLOW_ACTION_DENY		 	2
#define SYSFLOW_ACTION_REDIRECT  	3
#define SYSFLOW_ACTION_QRAUNTINE 	4
#define SYSFLOW_ACTION_ISOLATION   5
#define SYSFLOW_ACTION_MIGRATION 	6
#define SYSFLOW_ACTION_ENCODE		7
#define SYSFLOW_ACTION_DECODE 		8
#define SYSFLOW_ACTION_LOG	 		9
#define SYSFLOW_ACTION_REPORT 		10
#define SYSFLOW_ACTION_MESSAGE		11
#define SYSFLOW_ACTION_NEXTMODULE   12

//add customized sysflow action here




// #define KEY_SRC_SIZE max(sizeof(uint32_t), 0)
// #define KEY_DST_SIZE max(sizeof(struct file_id), 0)
#define KEY_SRC_SIZE (sizeof(uint32_t) + SFPFM_MAX_NAME)
#define KEY_DST_SIZE (sizeof(struct file_id) + SFPFM_MAX_NAME)

struct sysflow_key {
	union{
		uint32_t pid;		/*process id*/
	};
	char src_name[SFPFM_MAX_NAME];

	union{
		struct file_id fid;
	};

	char dst_name[SFPFM_MAX_NAME];

	uint32_t opcode;		/*sysflow operation ID for system events*/
};

struct sysflow_mask {
	struct sysflow_key key;
	
	uint32_t  key_mask;				/*bitwise mask for sysflow key, 
								8th digit for src, 7th for dst, 6th for opcode,
								rest digits are reserved*/
	
	//struct sysflow_key key_mask;	/*bitwise mask for sysflow key, 0 for wildcard bit*/
};

/*
struct sysflow_key_range {
	uint32_t start;
	uint32_t end;
};


struct sysflow_mask {
//	int ref_count;
//	struct rcu_head rcu;
	struct sysflow_key_range range;
	struct sysflow_key key;
};

struct sysflow_match {
	struct sysflow_key *key;
	struct sysflow_key_range range;
	struct sysflow_mask *mask;
};
*/

struct sysflow_action{
	int action_type;
	int len;
	struct sysflow_action *next;	/*pointer to next action if exit*/
	char* action_code;	/*parameters for sysflow action if necessary*/ 
};

struct sysflow_stats {
	int event_hits;
	int bytes_hits;
};

/*entry of flow table*/
struct sysflow_entry {
	struct rcu_head rcu;
	struct {
		struct hlist_node node[2];
		uint32_t hash;
	} sysflow_table;
//	int stats_last_writer;		/* NUMA-node id of the last writer on 'stats[0]'.*/

	struct sysflow_key key;
//	struct sysflow_id id;
	struct sysflow_mask *mask;
	struct sysflow_action __rcu *actions;	/*the head pointer of sysflow actions*/

	//TODO: supporting metadata
	struct sysflow_stats stats;
	/*struct flow_stats __rcu *stats[];  One for each NUMA node.  First one
					   * is allocated at flow creation time,
					   * the rest are allocated on demand
					   * while holding the 'stats[0].lock'.
					   */
};

/*entry for exact match*/
struct exact_match_entry {	
	uint32_t hash;
	uint32_t mask_index;
};

struct mask_array {
	struct rcu_head rcu;
	int count, max;
	struct sysflow_mask __rcu *masks[];
};


struct table_instance {
	struct flex_array *buckets;
	unsigned int n_buckets;
	struct rcu_head rcu;
	int node_ver;
	uint32_t hash_seed;
	bool keep_flows;
};

struct sysflow_table {
	struct table_instance __rcu *ti;

//	struct mask_cache_entry __percpu *mask_cache;	/*for exact match*/
	struct mask_array __rcu *mask_array;
//	unsigned long last_rehash;
	unsigned int count;
//	unsigned int ufid_count;
};

int sysflow_tbl_init(struct sysflow_table *table);
void sysflow_tbl_destroy(struct sysflow_table *table);

int sysflow_tbl_insert(struct sysflow_table *table, struct sysflow_entry *entry);
int sysflow_tbl_remove(struct sysflow_table *table, struct sysflow_entry *entry);


struct sysflow_entry *sysflow_tbl_lookup(struct sysflow_table *table,
				    const struct sysflow_key *key);

/*
struct sysflow *sysflow_tbl_lookup_exact(struct sysflow_table *,
					  const struct sysflow_match *);
*/

/*construct sysflow key for a system event*/
int sysflow_key_extract(struct sysflow_system_event *, struct sysflow_key *);

#endif /* sysflow.h */
