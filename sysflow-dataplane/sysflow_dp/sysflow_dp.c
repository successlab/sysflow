#include "sysflow_dp.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jianwei, Kevin, Ray and Hao");
MODULE_DESCRIPTION("sysflow dataplane kernel manager");

struct datapath *gDp;
EXPORT_SYMBOL(gDp);

struct sock *nl_sk = NULL;
// [H18] kevin, add a function to send a message to userspace for SFP_ACTION_REPORT
struct sock *nl_act_report_sk = NULL;


unsigned int pid_1 = 0;

static struct nf_hook_ops sysflow_nf_ops[] __read_mostly = {
  {
    .hook = sysflow_nf_out_hook,
    .owner = THIS_MODULE,
    .pf = NFPROTO_IPV4,
    .hooknum = NF_INET_LOCAL_OUT,
    .priority = NF_IP_PRI_FIRST,
  },
};

unsigned int byte4toi(unsigned char* p, unsigned int n) {
    unsigned int x = 0;
    unsigned int i = 0;
    for(; i < n; i++){
        x = (x<<8) + p[i];
    }
    return x;
}

// [H3] kevin, rename dp to gDp to avoid confusion and init code of dp should be done in module_init
void sysflow_init_flowtable(void)
{
    int ret;

    if(!gDp){
        struct sysflow_table *table = kmalloc(sizeof(struct sysflow_table), GFP_KERNEL);

        gDp = kmalloc(sizeof(struct datapath), GFP_KERNEL);

        gDp->table = table;

        // initialize flow table
        ret = sysflow_tbl_init(gDp->table);
        WARN_ON(ret != 0);
        
        printk(KERN_INFO "[SysFlow] Create datapath and flowtable \n");
    } 
    else{
        printk(KERN_INFO "[SysFlow] NOTE: datapath and flowtable have already been created\n");
    }
}

// [H4] kevin, clear code for datapath and flowtable
void sysflow_remove_flowtable(void)
{
    if(!gDp){
        printk(KERN_INFO "[SysFlow] Remove datapath and flowtable \n");
    }
    else{
        printk(KERN_INFO "[SysFlow] NOTE: datapath and flowtable have already been removed\n");
    }

}

void print_action(struct sysflow_action *header){
    struct sysflow_action *p = header;
    int i;
    while(p != NULL){
        printk(KERN_INFO "[print_action]action_type:%d    len:%d\n", p->action_type, p->len);

        // [H17]
	    //for(i = 0; i < (p->len - 8); i++){
	    for(i = 0; i < p->len; i++){
            printk(KERN_INFO "%02x ", *((unsigned char *)p->action_code+i));
	    }
        p = p->next;
    }
}

void initial_sfp_flow_report(struct sfp_flow_report *flow_report, uint16_t length, uint8_t type, uint32_t xid){
        flow_report->header.length = length;
        flow_report->header.type = type;
        flow_report->header.xid = xid;
}

// [H18] kevin, add a function to send a message to userspace for SFP_ACTION_REPORT
static void sysflow_nl_recv_null_msg(struct sk_buff *skb) {
    // do nothing
}

// [H18] kevin, add a function to send a message to userspace for SFP_ACTION_REPORT
void nl_send_action_report(struct utok_info* actreport, int msg_size) {
    struct sk_buff *skb;
    struct nlmsghdr *nlh;
    int res;

    skb = nlmsg_new(NLMSG_ALIGN(msg_size), GFP_KERNEL);
    if (!skb) {
        printk(KERN_INFO "[SysFlow] nlmsg allocation failure.\n");
        return;
    }

    nlh = nlmsg_put(skb, 0, 1, NLMSG_DONE, msg_size + 1, 0);

	memcpy(nlmsg_data(nlh), actreport, msg_size);
    res = nlmsg_multicast(nl_act_report_sk, skb, 0, NETLINK_USER_KTOU_GROUP, GFP_KERNEL);
    if (res < 0)
        printk(KERN_INFO "nlmsg_multicast() error: %d\n", res);
    else
        printk(KERN_INFO "[SysFlow] ACTION_REPORT has been sent successfully.\n");
}



static void netlink_recv_msg(struct sk_buff *skb) {
	struct nlmsghdr *nlh;
	int pid;
	struct sk_buff *skb_out;
	int msg_size;
	unsigned char *msg;
	int res;
	int ret;
    unsigned int pid_1 = 0;
    unsigned int mask_val = 0;
	//unsigned int uuid = 0;
	//unsigned int inode_num = 0;
	unsigned int opcode = 0;
    int i;
    struct utok_info ktou_stats_reply;      // kevin, flow stats reply
    struct utok_info ktou_act_report;       // [H19]
	//struct sfp_flow_report flow_report;
    //unsigned int len;
    struct utok_info *info;

	struct file_id fid_1;
    unsigned int priority;      // kevin
    unsigned int action_num;
    unsigned char * p;
	
    unsigned char* ptr; 
    //struct parsed_action *paction;
    struct sysflow_action *action_header = NULL;
    struct sysflow_action *action = NULL;
    struct sysflow_action *prev = NULL;    
    long delta_nsec;
    long delta_sec;
	static struct timespec old_time, new_time;

	printk(KERN_INFO "Sysflow kernel agent starts.\n");
    getnstimeofday(&old_time);

	printk(KERN_INFO "Entering: %s\n", __FUNCTION__);

	nlh = (struct nlmsghdr*)skb->data;
	printk(KERN_INFO "Netlink received msg payload:%s\n",(char*)nlmsg_data(nlh));
	pid = nlh->nlmsg_pid; 	/*pid of sending process */
	
    // [H7] fix missing assignment
    msg_size = nlh->nlmsg_len;

	msg = (unsigned char *)nlmsg_data(nlh);	/*get the attributes from Userspace in here*/	
    printk(KERN_INFO "Netlink received msg len: %d\n", msg_size);
    
    info = (struct utok_info *)msg;

    // kevin, debugging
	printk(KERN_INFO "utok_info.header.length: %d\n", info->header.length);
	printk(KERN_INFO "utok_info.header.type: %d\n", info->header.type);
	printk(KERN_INFO "utok_info.header.xid: %d\n", info->header.xid);

    if(SFP_FLOW_MOD == info->header.type){

        // ------------------------------------------------------
        // kevin, debugging
        // ------------------------------------------------------
        printk(KERN_INFO "---------------------------------------\n");
        printk(KERN_INFO " SysFlow Flow Mod Message \n");
        printk(KERN_INFO "---------------------------------------\n");
        printk(KERN_INFO "*** FlowMod Type: %d ***\n", info->protocol.flowmod.type);
	    printk(KERN_INFO "srctype: %d\n", info->protocol.flowmod.match.src_type);
        printk(KERN_INFO "srclen: %d\n", info->protocol.flowmod.match.src_len);
        printk(KERN_INFO "pid: %d\n", info->protocol.flowmod.match.pid);
        printk(KERN_INFO "srcname: %s\n", info->protocol.flowmod.match.src_name);
        printk(KERN_INFO "dsttype: %d\n", info->protocol.flowmod.match.dst_type);
        printk(KERN_INFO "dstlen: %d\n", info->protocol.flowmod.match.dst_len);
        printk(KERN_INFO "uuid: %d\n", info->protocol.flowmod.match.fid.uuid);
        printk(KERN_INFO "inode_num: %d\n", info->protocol.flowmod.match.fid.inode_num);
        printk(KERN_INFO "dstname: %s\n", info->protocol.flowmod.match.dst_name);
        printk(KERN_INFO "mask: %d\n", info->protocol.flowmod.match.mask);
        printk(KERN_INFO "opcode: %d\n", info->protocol.flowmod.match.opcode);

        printk(KERN_INFO "priority: %d\n", info->protocol.flowmod.priority);          
        printk(KERN_INFO "action_num: %d\n", info->protocol.flowmod.action_num);
        // ------------------------------------------------------

        pid_1 = info->protocol.flowmod.match.pid;
        mask_val = info->protocol.flowmod.match.mask;
        opcode = info->protocol.flowmod.match.opcode;
   
        fid_1.uuid = info->protocol.flowmod.match.fid.uuid; // kevin
        //TODO: parse UUID from client.c
        //fid_1.uuid = 0;
    
        priority = info->protocol.flowmod.priority;     // kevin

        fid_1.inode_num = info->protocol.flowmod.match.fid.inode_num;
        action_num = info->protocol.flowmod.action_num;

        // extract actions
        p = info->protocol.flowmod.action_buffer;
   
        // paction = (struct parsed_action *)kmalloc(sizeof(struct parsed_action)*action_num, GFP_KERNEL);

        for(i = 0; i < action_num; i++) {
            int j; 

            action = (struct sysflow_action *)kmalloc(sizeof(struct sysflow_action), GFP_KERNEL);  
            if(i == 0){
                action_header = action;
            } 
            if(prev != NULL){
                prev->next = action;
            } 
            // [H12]
            //ptr = (unsigned char *)kmalloc(byte4toi(p+4, 4)-8, GFP_KERNEL);
            ptr = (unsigned char *)kmalloc(byte4toi(p+4, 4), GFP_KERNEL);
            action->action_type = byte4toi(p,4);
            action->len = byte4toi(p+4,4);
                
            // [H12]
            //memcpy(ptr, p+8, byte4toi(p+4, 4)-8);
            memcpy(ptr, p+8, action->len);
            action->action_code = ptr;
            action->next = NULL;
            prev = action;
            printk(KERN_INFO "ptr:");
            // [H17]
            //for(j = 0; j < byte4toi(p+4, 4)-8; j++){
            for(j = 0; j < action->len; j++){
                printk(KERN_INFO "%02x ", *((unsigned char *)ptr+j));
	        }
            printk(KERN_INFO "\n");
            // print as a string for readability
            // [H17]
            //for(j = 0; j < byte4toi(p+4, 4)-8; j++){
            for(j = 0; j < action->len; j++){
                printk(KERN_INFO "%c", *((unsigned char *)ptr+j));
	        }
            printk(KERN_INFO "\n");


            // [H12]
            //p = p + byte4toi(p+4, 4);
            p += 8 /*sizeof(action_type + action_len)*/ + action->len;
        } // end for
    
        print_action(action_header);


	    printk(KERN_INFO "pid_1:%d    opcode:%d  uuid:%d    inode_num:%d\n", pid_1, opcode, fid_1.uuid, fid_1.inode_num);
	
        // [H14] kevin, should differentiate a workflow by flowmod type
        if(SFPFM_ADD == info->protocol.flowmod.type){

	        //struct sysflow_entry *entry_1 = create_exact_entry(pid_1, fid_1, opcode);
	        struct sysflow_entry *entry_1 = create_flow_entry(pid_1, fid_1, &(info->protocol.flowmod.match.src_name),
                                         &(info->protocol.flowmod.match.dst_name), opcode, mask_val, action_header);
            // [H3] kevin, rename dp to gDp to avoid confusion and init code of dp should be done in module_init
            //ret = test_sysflow_tbl_insert(dp, entry_1);
            ret = test_sysflow_tbl_insert(gDp, entry_1);


            // WARN_ON(ret != 0);
	        /*
	        int pid_2 = 2;
	        struct sysflow_entry *entry_2 = create_wildcard_entry(pid_2);
	        test_sysflow_tbl_insert(dp, entry_2);
	        printk(KERN_INFO "Passed test of flow rule insertion.\n");
	        */
	
            getnstimeofday(&new_time);
            delta_sec = new_time.tv_sec - old_time.tv_sec;
            delta_nsec = new_time.tv_nsec - old_time.tv_nsec;
            printk(KERN_INFO "[kernel:time] %ld,%ld\n", delta_sec, delta_nsec);
	        pr_info("Sysflow kernel agent ends.\n");

            // kevin, sends an ACK to client for completion of flow install
	        skb_out = nlmsg_new(msg_size,0);
	        if(!skb_out)
	        {
    	        printk(KERN_ERR "Failed to allocate new skb\n");
    	        return;
	        } 
	        nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE,msg_size,0);  
	        NETLINK_CB(skb_out).dst_group = 0; 		/* not in mcast group */
	
	        //initial_sfp_flow_report();
	        //msg = (char *) &flow_report;	
	        strncpy(nlmsg_data(nlh), msg, msg_size);
	        res = nlmsg_unicast(nl_sk, skb_out, pid);   /*return to userspace process*/

	        if(res < 0)
    	        printk(KERN_INFO "Error while sending back to user\n");
            else
                printk(KERN_INFO"[S2OS] managerKernel sends an ACK after a flow is created \n");    // kevin, debugging

        } // end if (SFPFM_ADD)
        // [H15] kevin, FIXME: should implement Flow Remove/Update
        else if(SFPFM_REMOVE == info->protocol.flowmod.type){
            /*test flow lookup*/
	        /*		
	        struct sysflow_system_event_hdr *event_hdr_1 = kmalloc(sizeof( struct sysflow_system_event_hdr), GFP_KERNEL);
	        event_hdr_1->src_type = SYSFLOW_SRC_PROCESS;
	        event_hdr_1->dst_type = SYSFLOW_DST_FILE;
	        event_hdr_1->opcode = SYSFLOW_FILE_APPEND;
	        event_hdr_1->pid = pid_1;
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
	        */
    
            /*
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
	        */
	        /*test flow removal*/
	        /*
	        ret = test_sysflow_tbl_remove(dp, entry_1);
	        WARN_ON(ret != 0);
	
	        ret = test_sysflow_tbl_remove(dp, entry_2);
	        WARN_ON(ret != 0);
	        */
	
	        /*
	        ret = sysflow_received_event(event_1, actions_1);
	        WARN_ON(ret == 0);	//can not find the rule any more
	
	        ret = sysflow_received_event(event_2, actions_2);
	        WARN_ON(ret == 0);	//can not find the rule any more
	        printk(KERN_INFO "Passed test of flow rule removal.\n");
	
	
	        */
	
            getnstimeofday(&new_time);
            delta_sec = new_time.tv_sec - old_time.tv_sec;
            delta_nsec = new_time.tv_nsec - old_time.tv_nsec;
            printk(KERN_INFO "[kernel:time] %ld,%ld\n", delta_sec, delta_nsec);
	        pr_info("Sysflow kernel agent ends.\n");

            // kevin, sends an ACK to client for completion of flow install
	        skb_out = nlmsg_new(msg_size,0);
	        if(!skb_out)
	        {
    	        printk(KERN_ERR "Failed to allocate new skb\n");
    	        return;
	        } 
	        nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE,msg_size,0);  
	        NETLINK_CB(skb_out).dst_group = 0; 		/* not in mcast group */
	
	        //initial_sfp_flow_report();
	        //msg = (char *) &flow_report;	
	        strncpy(nlmsg_data(nlh), msg, msg_size);
	        res = nlmsg_unicast(nl_sk, skb_out, pid);   /*return to userspace process*/

	        if(res < 0)
    	        printk(KERN_INFO "Error while sending back to user\n");
            else
                printk(KERN_INFO"[S2OS] managerKernel sends an ACK after a flow is created \n");    // kevin, debugging




        } // end if (SFPFM_REMOVE)

        // [H15] kevin, FIXME: should implement Flow Remove/Update
        else if(SFPFM_UPDATE == info->protocol.flowmod.type){
        } // end if (SFPFM_UPDATE)
        else{
            printk(KERN_INFO"[S2OS] Error: Undefined FlowMod type \n");
        } // end if 
    } // end if (SFP_FLOW_MOD)
    // [H16] kevin, FIXME: should implement Flow Stats Request
    else if(SFP_FLOW_STATE_REQUEST == info->header.type){
        // ------------------------------------------------------
        // kevin, debugging
        // ------------------------------------------------------
        printk(KERN_INFO "---------------------------------------\n");
        printk(KERN_INFO " SysFlow Flow Stats Request Message \n");
        printk(KERN_INFO "---------------------------------------\n");
	    printk(KERN_INFO "srctype: %d\n", info->protocol.statsreq.match.src_type);
        printk(KERN_INFO "srclen: %d\n", info->protocol.statsreq.match.src_len);
        printk(KERN_INFO "pid: %d\n", info->protocol.statsreq.match.pid);
        printk(KERN_INFO "srcname: %s\n", info->protocol.statsreq.match.src_name);
        printk(KERN_INFO "dsttype: %d\n", info->protocol.statsreq.match.dst_type);
        printk(KERN_INFO "dstlen: %d\n", info->protocol.statsreq.match.dst_len);
        printk(KERN_INFO "uuid: %d\n", info->protocol.statsreq.match.fid.uuid);
        printk(KERN_INFO "inode_num: %d\n", info->protocol.statsreq.match.fid.inode_num);
        printk(KERN_INFO "dstname: %s\n", info->protocol.statsreq.match.dst_name);
        printk(KERN_INFO "mask: %d\n", info->protocol.statsreq.match.mask);
        printk(KERN_INFO "opcode: %d\n", info->protocol.statsreq.match.opcode);

        // [H16] kevin, FIXME: should implement Flow Stats Request
        // HERE: Implement flow table lookup and extract the stats for the corresponding flow entry
        // test example
        memcpy(&ktou_stats_reply.header, &info->header, sizeof(struct sfp_header));
        ktou_stats_reply.header.type = SFP_FLOW_STATE_REPORT;
        ktou_stats_reply.header.length = sizeof(struct sfp_flow_stats_reply);
        memcpy(&ktou_stats_reply.protocol.statsrep.match, &info->protocol.statsreq.match, sizeof(struct sfp_match)); 

        // TODO: fill event_hits & byte_hits
        ktou_stats_reply.protocol.statsrep.event_hits = 100;
        ktou_stats_reply.protocol.statsrep.byte_hits = 200;

        // prepare nlmsg
        msg_size = sizeof(struct sfp_flow_stats_reply);
	    skb_out = nlmsg_new(msg_size,0);
	    if(!skb_out)
	    {
    	    printk(KERN_ERR "Failed to allocate new skb\n");
    	    return;
	    } 
	    nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE,msg_size,0);  
	    NETLINK_CB(skb_out).dst_group = 0; 		/* not in mcast group */
	
	    memcpy(nlmsg_data(nlh), &ktou_stats_reply, msg_size);
	    res = nlmsg_unicast(nl_sk, skb_out, pid);   /*return to userspace process*/

	    if(res < 0)
    	    printk(KERN_INFO "Error while sending back to user\n");
        else
            printk(KERN_INFO"[S2OS] managerKernel sends an ACK after a flow is created \n");    // kevin, debugging

        // ----------------------------------------------------------------------
        // [H20] kevin, TEST CODE for action report message
        // @note:   currently copied a header and match from stats request, but
        //          an action report should be filled from flow table lookup triggered by events
        // ----------------------------------------------------------------------
        // fill out a header
        memcpy(&ktou_act_report.header, &info->header, sizeof(struct sfp_header));
        ktou_act_report.header.type = SFP_ACTION_REPORT;
        // header.len should be the size of a message except the header size
        //ktou_act_report.header.len = sizeof(struct sfp_match) + 12 /*action_type+reason+data_len*/ + ktou_act_report.protocol.actreport.data_len;


        // update header.len at the end
        // fill out match
        memcpy(&ktou_act_report.protocol.actreport.match, &info->protocol.statsreq.match, sizeof(struct sfp_match)); 
        // get action type from the flow entry
        ktou_act_report.protocol.actreport.action_type = SYSFLOW_ACTION_DECODE;
        // action report reason
        ktou_act_report.protocol.actreport.reason = SYSFLOW_ACTION_REPORT_REASON_REPORT_TO_CONTROLLER | SYSFLOW_ACTION_REPORT_REASON_ALERT_TO_USER | SYSFLOW_ACTION_REPORT_REASON_STRING_MESSAGE;
        // set the corresponding reason data_len and data 

        strcpy(ktou_act_report.protocol.actreport.data, "Action Alert! Inform User and Controller");
        ktou_act_report.protocol.actreport.data_len = strlen(ktou_act_report.protocol.actreport.data);

        // FIXME: calc header.len here for test
        // header.len should be the size of a message except the header size
        ktou_act_report.header.length = sizeof(struct sfp_match) + 12 /*action_type+reason+data_len*/ + ktou_act_report.protocol.actreport.data_len;

        msg_size = sizeof(struct sfp_action_report);

        printk(KERN_INFO "[SysFlow] action_report.reason msg_len: %d\n", msg_size);
        printk(KERN_INFO "[SysFLow] Sending an action report: %s\n", ktou_act_report.protocol.actreport.data);

        nl_send_action_report(&ktou_act_report, msg_size);
    }
}

static int sysflow_lsm_register(void) {
    int ret;
    ret = s2os_save_sysflow_func(sysflow_received_event);
    if (0 == ret) {
        gStatus.sysflow_mode = S2OS_SYSFLOW_MOD_INIT;
    }
    pr_info("[S2OS-managerKernel] lsm hook registered.\n");
    return ret;
}

static int sysflow_lsm_unregister(void){
    int ret;
    pr_info("[S2OS-mangerKernel] lsm hook unregistered.\n");
    ret = s2os_rm_sysflow_func();
    if(0 == ret){
        gStatus.sysflow_mode = S2OS_SYSFLOW_MOD_NULL;
    }

    return ret;
}

static int sysflow_nf_register(void){
    int ret;
    ret = nf_register_hooks(sysflow_nf_ops, ARRAY_SIZE(sysflow_nf_ops));
    if(ret < 0){
        printk("[S2OS-managerKernel] failed to register nf hook.\n");
        return ret;
    }

    printk(KERN_NOTICE "[S2OS-managerKernel] netfilter hook registered. \n");
    return ret;
}

static int sysflow_nf_unregister(void){
    int ret = 0;
    printk(KERN_NOTICE "[S2OS-managerKernel] netfilter hook unregistered.\n");
    nf_unregister_hooks(sysflow_nf_ops, ARRAY_SIZE(sysflow_nf_ops));

    return ret;
}

static int sysflow_report_register(void){
    int ret;
    pr_info("[S2OS-mangerKernel] report function registered.\n");
    ret = s2os_save_report_func(nl_send_action_report);
    if(0 == ret){
        gStatus.sysflow_mode = S2OS_SYSFLOW_MOD_INIT;
    }

    return ret;
}

static int sysflow_report_unregister(void){
    int ret = 0;
    printk(KERN_NOTICE "[S2OS-managerKernel] report function unregistered.\n");
    ret = s2os_rm_report_func();
    if(0 == ret){
        gStatus.sysflow_mode = S2OS_SYSFLOW_MOD_NULL;
    }
    return ret;
}

static int __init sysflow_init(void) {
	printk("[S2OS-kernel] Initializing sysflow kernel manager\n");
    
	//This is for 3.6 kernels and above.
	/*
	struct netlink_kernel_cfg cfg = {
    		.input = netlink_recv_msg,
	};	
	nl_sk = netlink_kernel_create(&init_net, NETLINK_USER, &cfg);
	*/

    // Register for LSM. 
    if ( 0 != sysflow_lsm_register() ) {
	    printk(KERN_ALERT "[S2OS-kernel] cannot register lsm hook.\n");
        return -1;
    }

    // Register for netfilter
    if(0 != sysflow_nf_register()){
        printk(KERN_ALERT "[S2OS-kernel] cannot register netfilter hook.");
        return -1;
    }

    // Register for report function
    if(0 != sysflow_report_register()){
        printk(KERN_ALERT "[S2OS-kernel] cannot register report function.");
        return -1;
    }
    
    // Create netlink object
    nl_sk = netlink_kernel_create(&init_net, NETLINK_USER, 0, netlink_recv_msg, NULL, THIS_MODULE);
	if(!nl_sk)
	{
	    printk(KERN_ALERT "[S2OS-kernel] Error creating socket.\n");
        return -1;
	}

    // [H18] kevin, add a function to send a message to userspace for SFP_ACTION_REPORT
	//nl_act_report_sk = netlink_kernel_create(&init_net, NETLINK_USER_KTOU, 0, sysflow_nl_recv_null_msg, NULL, THIS_MODULE);
	nl_act_report_sk = netlink_kernel_create(&init_net, NETLINK_USER_KTOU, 0, sysflow_nl_recv_null_msg, NULL, THIS_MODULE);

	if(!nl_act_report_sk)
	{
	    printk(KERN_ALERT "Error creating action report socket.\n");
        return -1;
    }

    sysflow_init_flowtable();

	return 0;
}

static void __exit sysflow_exit(void) {
	printk(KERN_INFO "[S2OS-kernel] Exiting\n");

    sysflow_lsm_unregister();
    sysflow_nf_unregister();
    sysflow_report_unregister();

    // [H4] kevin, clear code for datapath and flowtable
    sysflow_remove_flowtable();

    // jianwei, release netlink
	netlink_kernel_release(nl_sk);
    netlink_kernel_release(nl_act_report_sk);
}

module_init(sysflow_init);
module_exit(sysflow_exit);
