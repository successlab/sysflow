#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

#include <linux/security.h>

#include <linux/sysflow.h>
#include <linux/sysflow_event.h>

#include "sysflow_loadable.h"

MODULE_LICENSE("GPL");

static struct datapath *dp;
/*
* Todo: use a better hash. 
* Assume s_uuid is an arry of size 16 of uint8_t 
*
* */
static inline uint32_t hash_uuid(uint8_t *s_uuid) {
    uint32_t ret = *((uint32_t*)s_uuid);
    ret += *((uint32_t*)(s_uuid+4));
    ret += *((uint32_t*)(s_uuid+8));
    ret += *((uint32_t*)(s_uuid+12));
    return ret;
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


    key = (struct sysflow_key*)kmalloc(sizeof(struct sysflow_key), GFP_KERNEL);
    
    error = sysflow_key_extract(sse, key);
    printk(KERN_INFO "[S2OS] Sysflow: fid.uuid=%d; fid.inode_num=%d\n", key->fid.uuid, key->fid.inode_num);


    if(error == -1){
        return error;
    }
    
    table = dp->table;
    if(!table){
        return -1;
    }

    entry = sysflow_tbl_lookup(table, key);
    if(!entry){
        printk(KERN_INFO "[S2OS] SYSFLOW: no flow rule match.\n");
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


static struct flow_entry *create_wildcard_pid_entry(struct file_id fid, int opcode) {
    struct sysflow_key key;
    key.fid = fid;
    key.opcode = opcode;

    struct sysflow_mask *mask = kmalloc(sizeof(*mask), GFP_KERNEL);
    mask->key = key;
    mask->key_mask = 6;
    
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



static int sysflow_lsm_register(void) {
    int ret;
    pr_info("[S2OS] Sysflow: register lsm.\n");
    ret = s2os_save_sysflow_func(sysflow_received_event);
    if (0 == ret) {
        gStatus.sysflow_mode = S2OS_SYSFLOW_MOD_INIT;
    }
    return ret;
}


static void sysflow_lsm_unregister(void) {
    pr_info("[S2OS] Sysflow: unregister lsm.\n");
    gStatus.sysflow_mode = S2OS_SYSFLOW_MOD_INIT;
}



static int __init sysflow_lsm_test_init(void) {
    int ret;
    char s_uuid[16] = {0xb2, 0xdf, 0xa5, 0x27, 0x1d, 0xd0, 0x4b, 0xf8, 0x88, 0x95, 0xac, 0x79, 0xc2, 0x02, 0x7d, 0xd7};

    // pr_info("Sysflow kernel agent starts.\n");
    printk(KERN_INFO "[S2OS] Sysflow: Going to initialize module. \n"); 

    // Register for LSM. 
    if ( 0 != sysflow_lsm_register() ) {
        WARN_ON("[S2OS] Sysflow: can't register for LSM.\n Going to abard.\n");
        return -1;
    }

    /*initialize datapath*/
    dp = kmalloc(sizeof(struct datapath), GFP_KERNEL);
    struct sysflow_table *table = kmalloc(sizeof(struct sysflow_table), GFP_KERNEL);

    dp->table = table;

    /*initialize flow table*/
    ret = sysflow_tbl_init(dp->table);
    WARN_ON(ret != 0);

    struct file_id fid;
    // insert flow to deny write
    fid.uuid = hash_uuid(s_uuid);
    fid.inode_num = 1454385;
    struct sysflow_entry *entry_1 = create_wildcard_pid_entry(fid, SYSFLOW_FILE_WRITE);
    ret = test_sysflow_tbl_insert(dp, entry_1);
    WARN_ON(ret != 0);
    // insert flow to deny read 
    fid.uuid = hash_uuid(s_uuid);
    fid.inode_num = 1451775;
    struct sysflow_entry *entry_2 = create_wildcard_pid_entry(fid, SYSFLOW_FILE_READ);
    ret = test_sysflow_tbl_insert(dp, entry_2);
    WARN_ON(ret != 0);

    return 0;
}

static void __exit sysflow_lsm_test_exit(void) {
    sysflow_lsm_unregister();
    printk(KERN_INFO "Going to exit test module.\n");
}

module_init(sysflow_lsm_test_init);
module_exit(sysflow_lsm_test_exit);


