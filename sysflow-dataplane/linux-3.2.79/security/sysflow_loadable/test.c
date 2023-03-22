#include <linux/module.h>
#include <net/sock.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/security.h>

//for testing
#include "/home/haojin/sysflow/linux-3.2.0/include/linux/sysflow.h"
#include "/home/haojin/sysflow/linux-3.2.0/include/linux/sysflow_event.h"

#include "sysflow_loadable.h"

static struct datapath *dp;


#define NETLINK_USER 31

struct sock *nl_sk = NULL;


/*
 * LSM callback functions for handling sysflow system events
 * */
int sysflow_received_event(struct sysflow_system_event* sse,
            struct sysflow_action *action) {
    
    struct sysflow_key *key;
    struct sysflow_entry *entry;
    struct sysflow_table *table;

    int error;

    //TODO: check system event is valid
    if (!sse) {
        return -1;
    }


    key  = kmalloc(sizeof(struct sysflow_key), GFP_KERNEL);
    
    error = sysflow_key_extract(sse, key);
    if(error == -1){
        return error;
    }
    
    table = dp->table;
    if(!table){
        return -1;
    }

    entry = sysflow_tbl_lookup(table, key);
    if(!entry){
        printk(KERN_INFO "[Sysflow Test] no flow rule match.\n");
        return -1;
    }

    *action = *(entry->actions);
    return 0;
}

static struct flow_entry *create_exact_entry(int pid, struct file_id fid, int opcode){
    struct sysflow_key key;
    key.pid = pid;
    key.fid = fid;
    key.opcode = SYSFLOW_FILE_APPEND;

    struct sysflow_mask *mask = kmalloc(sizeof(*mask), GFP_KERNEL);
    mask->key = key;
    mask->key_mask = 7;

    struct sysflow_action *action = kmalloc(sizeof(*action), GFP_KERNEL);
    action->action_type = SYSFLOW_ACTION_ALLOW;
    action->len = sizeof(struct sysflow_action);
    action->next = NULL;

    struct sysflow_entry *entry = kmalloc(sizeof(*entry), GFP_KERNEL);
    entry->key = key;
    entry->mask = mask;
    entry->actions = action;

    return entry;
}

static struct flow_entry *create_wildcard_entry(int pid){
    struct sysflow_key key;
     key.pid = pid;

    struct sysflow_mask *mask = kmalloc(sizeof(*mask), GFP_KERNEL);
    mask->key = key;
    mask->key_mask = 1;

    struct sysflow_action *action = kmalloc(sizeof(struct sysflow_action), GFP_KERNEL);
    action->action_type = SYSFLOW_ACTION_DENY;
    action->len = sizeof(struct sysflow_action);
    action->next = NULL;

    struct sysflow_entry *entry = kmalloc(sizeof(struct sysflow_entry), GFP_KERNEL);
    entry->key = key;
    entry->mask = mask;
    entry->actions = action;

    return entry;
}


static int test_sysflow_tbl_insert(struct datapath *dp, struct sysflow_entry *entry){
    int ret;

    struct sysflow_table *table = dp->table;

    
    ret = sysflow_tbl_insert(table, entry);
    
    return ret;

}

static int test_sysflow_tbl_remove(struct datapath *dp, struct sysflow_entry *entry){
    int ret;

    struct sysflow_table *table = dp->table;

    
    ret = sysflow_tbl_remove(table, entry);
    
    return ret;

}



static void hello_nl_recv_msg(struct sk_buff *skb) {

	struct nlmsghdr *nlh;
	int pid;
	struct sk_buff *skb_out;
	int msg_size;
	char *msg;
	int res;
	int ret;

	pr_info("Sysflow kernel agent starts.\n");

    	/*initialize datapath*/
    	dp = kmalloc(sizeof(struct datapath), GFP_KERNEL);
    	struct sysflow_table *table = kmalloc(sizeof(struct sysflow_table), GFP_KERNEL);

    	dp->table = table;

    	/*initialize flow table*/
    	ret = sysflow_tbl_init(dp->table);
    	WARN_ON(ret != 0);
	
	printk(KERN_INFO "Entering: %s\n", __FUNCTION__);

	nlh = (struct nlmsghdr*)skb->data;
	printk(KERN_INFO "Netlink received msg payload:%s\n",(char*)nlmsg_data(nlh));
	pid = nlh->nlmsg_pid; 	/*pid of sending process */
	
	msg = (char *)nlmsg_data(nlh);	/*get the attributes from Userspace in here*/	
	msg_size = strlen(msg);

	/*test flow table insertion*/
	int pid_1 = 1;
	struct file_id fid_1;
	fid_1.uuid = 1;
	fid_1.inode_num = 1;
	struct sysflow_entry *entry_1 = create_exact_entry(pid_1, fid_1, SYSFLOW_FILE_APPEND);
	ret = test_sysflow_tbl_insert(dp, entry_1);
	WARN_ON(ret != 0);
	
	int pid_2 = 2;
	struct sysflow_entry *entry_2 = create_wildcard_entry(pid_2);
	test_sysflow_tbl_insert(dp, entry_2);
	printk(KERN_INFO "Passed test of flow rule insertion.\n");
	
	
	/*test flow lookup*/
	struct sysflow_system_event_hdr *event_hdr_1 = kmalloc(sizeof( struct sysflow_system_event_hdr), GFP_KERNEL);
	event_hdr_1->src_type = SYSFLOW_SRC_PROCESS;
	event_hdr_1->dst_type = SYSFLOW_DST_FILE;
	event_hdr_1->opcode = SYSFLOW_FILE_APPEND;
	event_hdr_1->pid = 1;
	event_hdr_1->fid = fid_1;
	
	struct sysflow_system_event *event_1 = kmalloc(sizeof(struct sysflow_system_event), GFP_KERNEL);
	event_1->len = sizeof(struct sysflow_system_event);
	event_1->hdr = event_hdr_1;
	event_1->payload = NULL;
	
	
	struct sysflow_action *actions_1 = kmalloc(sizeof(struct sysflow_action), GFP_KERNEL);
	ret = sysflow_received_event(event_1, actions_1);
	WARN_ON(ret != 0);
	WARN_ON(actions_1->action_type != SYSFLOW_ACTION_ALLOW);
	WARN_ON(actions_1->next);
	printk(KERN_INFO "Passed the test of exact flow rule searching.\n");
	
	struct sysflow_system_event_hdr *event_hdr_2 = kmalloc(sizeof( struct sysflow_system_event_hdr), GFP_KERNEL);
	event_hdr_2->src_type = SYSFLOW_SRC_PROCESS;
	event_hdr_2->dst_type = SYSFLOW_DST_FILE;
	event_hdr_2->opcode = SYSFLOW_FILE_APPEND;
	event_hdr_2->pid = 2;
	event_hdr_2->fid = fid_1;
	
	struct sysflow_system_event *event_2 = kmalloc(sizeof(struct sysflow_system_event), GFP_KERNEL);
	event_2->len = sizeof(struct sysflow_system_event);
	event_2->hdr = event_hdr_2;
	event_2->payload = NULL;
	
	struct sysflow_action *actions_2 = kmalloc(sizeof(struct sysflow_action), GFP_KERNEL);
	ret = sysflow_received_event(event_2, actions_2);
	WARN_ON(ret != 0);
	WARN_ON(actions_2->action_type != SYSFLOW_ACTION_DENY);
	WARN_ON(actions_2->next);
	printk(KERN_INFO "Passed the test of wildcard flow rule searching.\n");
	   
	/*test flow removal*/
	ret = test_sysflow_tbl_remove(dp, entry_1);
	WARN_ON(ret != 0);
	
	ret = test_sysflow_tbl_remove(dp, entry_2);
	WARN_ON(ret != 0);
	
	ret = sysflow_received_event(event_1, actions_1);
	WARN_ON(ret == 0);	//can not find the rule any more
	
	ret = sysflow_received_event(event_2, actions_2);
	WARN_ON(ret == 0);	//can not find the rule any more
	printk(KERN_INFO "Passed test of flow rule removal.\n");
	
	
	pr_info("Sysflow kernel agent ends.\n");



	
	skb_out = nlmsg_new(msg_size,0);

	if(!skb_out)
	{
    	    printk(KERN_ERR "Failed to allocate new skb\n");
    	    return;
	} 
	nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE,msg_size,0);  
	NETLINK_CB(skb_out).dst_group = 0; 		/* not in mcast group */
	strncpy(nlmsg_data(nlh), msg, msg_size);

	res = nlmsg_unicast(nl_sk, skb_out, pid);   /*return to userspace process*/

	if(res < 0)
    	    printk(KERN_INFO "Error while sending bak to user\n");
}

static int __init hello_init(void) {

	printk("Entering: %s\n",__FUNCTION__);
	//This is for 3.6 kernels and above.
	/*
	struct netlink_kernel_cfg cfg = {
    		.input = hello_nl_recv_msg,
	};	
	nl_sk = netlink_kernel_create(&init_net, NETLINK_USER, &cfg);
	*/
	nl_sk = netlink_kernel_create(&init_net, NETLINK_USER, 0, hello_nl_recv_msg,NULL, THIS_MODULE);
	if(!nl_sk)
	{
	    printk(KERN_ALERT "Error creating socket.\n");
    	    return -1;
	}

	return 0;
}

static void __exit hello_exit(void) {

	printk(KERN_INFO "exiting hello module\n");
	netlink_kernel_release(nl_sk);
}

module_init(hello_init);
module_exit(hello_exit);

MODULE_LICENSE("GPL");
