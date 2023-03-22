#include <linux/module.h>
#include <net/sock.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <linux/init.h>
#include <linux/kernel.h>

#include <linux/types.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

#include <linux/sysflow.h>
#include <linux/sysflow_event.h>

#include <linux/protocol.h>
#include <linux/security.h>

/*definitions for generic netlink*/
#define SYSFLOW_FLOW_FAMILY "sysflow_flow"
#define SYSFLOW_VERSION 0x1 
#define NETLINK_USER 31
// [H18] kevin, add a function to send a message to userspace for SFP_ACTION_REPORT
#define NETLINK_USER_KTOU 17 
#define NETLINK_USER_KTOU_GROUP 1
#define MAX_PAYLOAD 1024

/*RCU defintions*/
#define sf_rcu_update_dereference(p)					\
	rcu_dereference_protected(p, 1)
#define sf_rcu_read_dereference(p)					\
	rcu_dereference_check(p, 1)

struct parsed_action {
    unsigned int type;
    unsigned int len;
    unsigned char *content;
};

struct datapath {
    //  struct rcu_head rcu;
    // struct list_head list_node;

    /* Flow table. */
    struct sysflow_table *table;
};

extern struct sysflow_entry *create_flow_entry(int pid, struct file_id fid, char *src_name, char *dst_name, int opcode, int mask_val, struct sysflow_action *action);
extern struct flow_entry *create_exact_entry(int pid, struct file_id fid, int opcode);
extern struct flow_entry *create_wildcard_entry(int pid);
extern int test_sysflow_tbl_insert(struct datapath *dp, struct sysflow_entry *entry);
extern int test_sysflow_tbl_remove(struct datapath *dp, struct sysflow_entry *entry);

unsigned int sysflow_nf_out_hook(unsigned int hook, struct sk_buff *skb, const struct net_device *in, 
                                        const struct net_device *out, int (*okfn)(struct sk_buff*));

extern int sysflow_received_event(struct sysflow_system_event* sse,
                                struct sysflow_action *action);
