#include "lsm_hooker.h"

int count = 0;

/*
 * LSM callback functions for handling sysflow system events
 * */
int sysflow_received_event(struct sysflow_system_event* sse,
            struct sysflow_action *action) {
    
    struct sysflow_key *key;
    struct sysflow_entry *entry;
    struct sysflow_table *table;

    int error,i;

    count++;

    pr_info("[S2OS - lsm_hooker] Received one event. count: %d\n", count);
    //TODO: check system event is valid
    if (!sse) {
        return -1;
    }

    key  = kmalloc(sizeof(struct sysflow_key), GFP_NOWAIT);
    memset(key, 0, sizeof(struct sysflow_key));
    error = sysflow_key_extract(sse, key);

    printk("[S2OS - lsm_hooker] key->fid: %d, opcode: %d\n", key->fid.inode_num, key->opcode);
    printk("[S2OS - lsm_hooker] key->src_name: %s, key->dst_name: %s\n", key->src_name, key->dst_name);

    if(error == -1){
        kfree(key);
        return error;
    }

    if(!gDp){
        return -1;
    }

    table = gDp->table;

    if(!table){
        return -1;
    }

    entry = sysflow_tbl_lookup(table, key);
    if(!entry){
        printk(KERN_INFO "[Sysflow Test] no flow rule match.\n");
        return -1;
    }

    entry->stats.event_hits++;

    memcpy(action, entry->actions, sizeof(*action));
    printk("[lsm_hooker.c - sysflow_received_event] action: type:%2d, len:%2d.\n", action->action_type, action->len);
    for(i=0; i < action->len; i++){
        printk("%c", (action->action_code)[i]);
    }
    return 0;
}
