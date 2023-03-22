#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

#include <linux/security.h>
//#include <linux/sysflow.h>
//#include <linux/sysflow_event.h>

//for testing
#include "/home/ray/sysflow/linux-3.2.0/include/linux/sysflow.h"
#include "/home/ray/sysflow/linux-3.2.0/include/linux/sysflow_event.h"

#include "sysflow_loadable.h"


static struct datapath *dp;

/*handler for flow installation messages from user space
TODO: add error handling functions
*/
static int sysflow_flow_cmd_new(struct sk_buff *skb, struct genl_info *info){
    /*headers*/
    struct nlmsghdr *nlhdr;
    struct genlmsghdr *genlhdr;
    struct nlattr *nlh;
    struct nlattr **attrs = info->attrs;
    struct sk_buff *reply;

    struct sysflow_entry *entry = kmalloc(sizeof(struct sysflow_entry), GFP_KERNEL);
    struct sysflow_key key;
    struct sysflow_mask *mask = kmalloc(sizeof(struct sysflow_mask), GFP_KERNEL);
    struct sysflow_action *action = kmalloc(sizeof(struct sysflow_action), GFP_KERNEL);
    struct sysflow_entry *entry = kmalloc(sizeof(struct sysflow_entry), GFP_KERNEL);

    int ret;

    /*
    nlhdr = nlmsg_hdr(skb);
    genlhdr = nlmsg_data(nlhdr);
    nlh = genlmsg_data(genlhdr);
    */


    /*check attribute of flow key and actions*/
    if (!attrs[SYSFLOW_FLOW_KEY]) {
        OVS_NLERR(log, "Flow key attr not present in new flow.");
        goto error;
    }
    if (!attrs[SYSFLOW_FLOW_ACTION]) {
        OVS_NLERR(log, "Flow action attr not present in new flow.");
        goto error;
    }

    ret = sysflow_get_flow_key_mask(entry, 
                                    attrs[SYSFLOW_FLOW_KEY]);
   
    if(ret == -1){
        goto error;
    }

    ret = sysflow_get_flow_actions(entry, 
                                    attrs[SYSFLOW_FLOW_ACTIONS]);

    if(ret == -1){
        goto error;
    }

    struct sysflow_table *table = dp->table;

    //TODO: check duplicated flow and update actions
    ret = sysflow_tbl_insert(table, entry);

    if(ret == -1){
        goto error;
    }

    return 0;

error:
    return -1;
}

/*handler for flow removal messages from user space
TODO: add error handling functions
*/
static int sysflow_flow_cmd_del(struct sk_buff *skb, struct genl_info *info){
    /*headers*/
    struct nlmsghdr *nlhdr;
    struct genlmsghdr *genlhdr;
    struct nlattr *nlh;
    struct nlattr **attrs = info->attrs;
    struct sk_buff *reply;

    struct sysflow_entry *entry = kmalloc(sizeof(struct sysflow_entry), GFP_KERNEL);
    struct sysflow_key key;
    struct sysflow_mask *mask = kmalloc(sizeof(struct sysflow_mask), GFP_KERNEL);
    struct sysflow_action *action = kmalloc(sizeof(struct sysflow_action), GFP_KERNEL);
    struct sysflow_entry *entry = kmalloc(sizeof(struct sysflow_entry), GFP_KERNEL);

    int ret;

    /*
    nlhdr = nlmsg_hdr(skb);
    genlhdr = nlmsg_data(nlhdr);
    nlh = genlmsg_data(genlhdr);
    */


    /*check attribute of flow key and actions*/
    if (!attrs[SYSFLOW_FLOW_KEY]) {
        OVS_NLERR(log, "Flow key attr not present in new flow.");
        goto error;
    }

    ret = sysflow_get_flow_key_mask(entry, 
                                    attrs[SYSFLOW_FLOW_KEY]);
   
    if(ret == -1){
        goto error;
    }

    struct sysflow_table *table = dp->table;

    //TODO: check duplicated flow and update actions
    ret = sysflow_tbl_remove(table, entry);

    if(ret == -1){
        goto error;
    }

    return 0;

error:
    return -1;
}

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


static void sysflow_unregister_genl(void){
    genl_unregister_family(sysflow_flow_genl_family);
}

/*private init functions************************************************/
static int sysflow_register_genl(void){
    int err;

    err =  genl_register_family(sysflow_flow_genl_family);

    if (err)
            goto error;
    
    return 0;

error:
    sysflow_unregister_genl();
    return err;
}

static void datapath_init(void){
    dp = kmalloc(sizeof(*dp), GFP_KERNEL);
}
/***********************************************************************/

/*sysflow kernel init function*/
static int __init sysflow_loadable_init(void) {
    int ret;

    pr_info("Sysflow kernel agent starts.\n");

    /*initialize datapath*/
    datapath_init();
   
    /*initialize flow table*/
    ret = sysflow_tbl_init(dp->table);
    WARN_ON(ret != 0);


    /*
    // register interface that will be called by lsm 
    ret = s2os_save_sysflow_func(sysflow_received_event);
    // modify status 
    gStatus.sysflow_mode = S2OS_SYSFLOW_MOD_INIT;
    */
    
    /*register generic netlink */
    ret = sysflow_register_genl();

    pr_info("Sysflow kernel agent ends.\n");
    return ret; 
}

static void __exit sysflow_loadable_exit(void) {
    sysflow_unregister_genl();

    printk(KERN_INFO "Going to exit test module.\n");
}

module_init(sysflow_loadable_init);
module_exit(sysflow_loadable_exit);
