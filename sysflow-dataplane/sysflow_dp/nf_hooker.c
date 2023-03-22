#include "nf_hooker.h"

char client[15] = "192.168.85.135";
char server[15] = "192.168.150.1";

static void sweep_event(struct sysflow_system_event *event) {
    if (event) {
        if (event->hdr) {
            kfree(event->hdr); 
        }
        kfree(event);
    }
}

static void sweep_action(struct sysflow_action *action) {
    if (action) {
        kfree(action);
    }
}

static inline uint32_t hash_uuid(uint8_t *s_uuid) { 
    uint32_t ret = *((uint32_t*)s_uuid);
    ret += *((uint32_t*)(s_uuid+4));
    ret += *((uint32_t*)(s_uuid+8));
    ret += *((uint32_t*)(s_uuid+12));

    return ret;
}

unsigned int ip_str_to_num(const char *buf)
{
    unsigned int tmpip[4] = {0};
    unsigned int tmpip32 = 0;
    sscanf(buf, "%d.%d.%d.%d", &tmpip[0], &tmpip[1], &tmpip[2], &tmpip[3]);
    tmpip32 = (tmpip[3]<<24) | (tmpip[2]<<16) | (tmpip[1]<<8) | tmpip[0];
    return tmpip32;
}

void hdr_dump(struct ethhdr *ehdr) {
    /*
    printk("[DMAC:%x:%x:%x:%x:%x:%x	SMAC: %x:%x:%x:%x:%x:%x	    Protype:%x]\n",
           ehdr->h_dest[0],ehdr->h_dest[1],ehdr->h_dest[2],ehdr->h_dest[3],
           ehdr->h_dest[4],ehdr->h_dest[5],ehdr->h_source[0],ehdr->h_source[1],
           ehdr->h_source[2],ehdr->h_source[3],ehdr->h_source[4],
           ehdr->h_source[5],ehdr->h_proto);
`   */
}

#define NIPQUAD(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[3]
#define NIPQUAD_FMT "%u.%u.%u.%u"

unsigned int
sysflow_nf_out_hook(unsigned int hook, struct sk_buff *skb, const struct net_device *in,
                const struct net_device *out, int (*okfn)(struct sk_buff*)) {
    struct ethhdr *eth_header;
    struct iphdr *ip_header;
    struct tcphdr *tcp_header;
    int lay4_len;
    int tcp_checksum = -1;
    int ret;
    
    unsigned int decision;

    struct sysflow_system_event *event = NULL;
    struct sysflow_action *action = NULL;

    eth_header = (struct ethhdr *)(skb_mac_header(skb));
    ip_header = (struct iphdr *)(skb_network_header(skb));
    tcp_header = (struct tcphdr *) (tcp_hdr(skb));
    lay4_len = skb->len - (ip_header->ihl << 2);

    if(S2OS_SYSFLOW_MOD_INIT == gStatus.sysflow_mode){
        event = (struct sysflow_system_event *)kmalloc(sizeof(struct sysflow_system_event), GFP_NOWAIT);
        if(NULL != event){
            memset(event, 0, sizeof(struct sysflow_system_event));

            event->len = sizeof(struct sysflow_system_event);
            event->hdr = (struct sysflow_system_event_hdr *)kmalloc(sizeof(*(event->hdr)), GFP_NOWAIT);
            if(NULL != event->hdr){
                memset(event->hdr, 0, sizeof(struct sysflow_system_event_hdr));
                event->hdr->src_type = SYSFLOW_SRC_PROCESS;
                event->hdr->pid = current->pid;

                event->hdr->dst_type = SYSFLOW_DST_SOCKET;
                sprintf(event->hdr->dst_name, ""NIPQUAD_FMT"", NIPQUAD(ip_header->daddr));
                //event->hdr->fid.uuid = hash_uuid();
                //event->hdr->fid.inode_num = file;
                event->hdr->opcode = SYSFLOW_SOCKET_WRITE;
            } else {
                printk("[S2OS - nf_hooker] failed to alloc memory for event->hdr\n");
                goto ALLOW;
            }
        } else {
            /* TODO: handle memory allocation */
            printk("[S2OS - nf_hooker] failed to alloc memory for event\n");
            goto ALLOW;
        }

        printk("[nf_hooker.c - nf_out_hook]pid: %d\n", event->hdr->pid);

        action = (struct sysflow_action*)kmalloc(sizeof(*action), GFP_NOWAIT);
        memset(action, 0, sizeof(struct sysflow_action));
        if (NULL != action) {
            // call sysflow interface
            ret = s2os_invoke_sysflow_func((void*)(event), (void*)action);
        }

        printk("[S2os - nf_hooker] sysflow action ret: %d\n", ret);

        while(ret != SYSFLOW_ACTION_UNKNOWN && action){
            printk(KERN_INFO "[S2OS - nf_hooker] action->type: %d\n", action->action_type);
            switch (action->action_type) {
                case SYSFLOW_ACTION_ALLOW: {
                    decision = NF_ACCEPT;
                    break;
                }
                case SYSFLOW_ACTION_DENY: {
                    decision = NF_DROP;
                    break;
                }
                case SYSFLOW_ACTION_REDIRECT: {
                    // TODO: redirect to another dst, change the dst IP & port num
                    decision = NF_ACCEPT;
                    break;
                }
                case SYSFLOW_ACTION_ENCODE:{
                    int oldtos = ip_header->tos;
                    char *tag_string = (char *)kmalloc(action->len+1,GFP_ATOMIC);
                    unsigned int tag = 0;
                    // TODO: add the tag into ToS field of IP protocol
                    hdr_dump(eth_header);
                    
                    tag = byte4toi(action->action_code, action->len);
                    ip_header->tos = tag;

                    printk("[nf_hooker.c - SYSFLOW_ACTION_ENCODE] action_code(tag): %d\n", tag);
                    csum_replace2(&ip_header->check, htons(oldtos), htons(ip_header->tos));

                    // printk("[nf_hooker.c - SYSFLOW_ACTION_ENCODE] src IP:'"NIPQUAD_FMT"', dst IP:'"NIPQUAD_FMT"' \n",
                    //         NIPQUAD(ip_header->saddr), NIPQUAD(ip_header->daddr));
                    // tcp_header->res1 = 0x0f;
                    // tcp_header->check = 0;
                    // tcp_checksum = csum_tcpudp_magic(ip_header->saddr, ip_header->daddr, lay4_len, IPPROTO_TCP, csum_partial(tcp_header, lay4_len, 0));
                    
                    // if (tcp_checksum != 0) {
                    //     printk("[nf_hooker.c - SYSFLOW_ACTION_ENCODE] TCP Checksum is %x\n", tcp_checksum);
                    // }

                    // tcp_header->check = tcp_checksum;
                    skb->ip_summed = CHECKSUM_NONE;
                    /*Recalculate IPCheckSum*/
                    //ip_send_check(ip_header);             //implicit declaration of function ‘ip_send_check’
                    ip_header->check = 0;
                    ip_header->check = ip_fast_csum((unsigned char *) ip_header, ip_header->ihl);
                    decision = NF_ACCEPT;
                    break;
                }
                case SYSFLOW_ACTION_DECODE:{
                    // TODO: shouldn't be used in socket_output. When in socket_input, extract the tag info & check it
                    decision = NF_ACCEPT;
                    break;
                }
                case SYSFLOW_ACTION_REPORT:{
                    struct utok_info ktou_act_report;
                    int msg_size;

                    ktou_act_report.header.type = SFP_ACTION_REPORT;
                    // FIXME: use a reasonable xid
                    ktou_act_report.header.xid = 0;
                    // header.len should be the size of a message except the header size

                    // update header.len at the end
                    // fill out match
                    memset(&ktou_act_report.protocol.actreport.match, 0, sizeof(struct sfp_match)); 
                    // get action type from the flow entry
                    ktou_act_report.protocol.actreport.action_type = SYSFLOW_ACTION_REPORT;
                    // action report reason
                    ktou_act_report.protocol.actreport.reason = SYSFLOW_ACTION_REPORT_REASON_REPORT_TO_CONTROLLER | SYSFLOW_ACTION_REPORT_REASON_STRING_MESSAGE;
                    // set the corresponding reason data_len and data 

                    sprintf(ktou_act_report.protocol.actreport.data, "Alert! '"NIPQUAD_FMT"' is sending data to '"NIPQUAD_FMT"'\n",
                            NIPQUAD(ip_header->saddr), NIPQUAD(ip_header->daddr));

                    ktou_act_report.protocol.actreport.data_len = strlen(ktou_act_report.protocol.actreport.data);

                    // FIXME: calc header.len here for test
                    // header.len should be the size of a message except the header size
                    ktou_act_report.header.length = sizeof(struct sfp_match) + 12 /*action_type+reason+data_len*/ + ktou_act_report.protocol.actreport.data_len;

                    msg_size = sizeof(struct sfp_action_report);

                    printk(KERN_INFO "[SysFlow] action_report.reason msg_len: %d\n", msg_size);
                    printk(KERN_INFO "[SysFLow] Sending an action report: %s\n", ktou_act_report.protocol.actreport.data);

                    nl_send_action_report(&ktou_act_report, msg_size);

                    decision = NF_ACCEPT;
                    break;
                }
                case SYSFLOW_ACTION_QRAUNTINE:
                case SYSFLOW_ACTION_ISOLATION:
                case SYSFLOW_ACTION_MIGRATION:
                case SYSFLOW_ACTION_LOG:
                case SYSFLOW_ACTION_MESSAGE:
                case SYSFLOW_ACTION_NEXTMODULE:
                    printk(KERN_INFO "[S2OS - nf_hooker] Action not implemented yet.\n");
                default:
                    decision = NF_ACCEPT;
                    break;
            }

            action = action->next;
        }

        if(decision == NF_ACCEPT){
            goto ALLOW;
        } else if (decision == NF_DROP){
            goto DENY;
        }
    }


ALLOW:
    sweep_event(event);
    sweep_action(action);

    return NF_ACCEPT;

DENY:
    sweep_event(event);
    sweep_action(action);

    return NF_DROP;
}


unsigned int
sysflow_nf_in_hook(unsigned int hook, struct sk_buff *skb, const struct net_device *in,
                const struct net_device *out, int (*okfn)(struct sk_buff*)) {
    struct ethhdr *eth_header;
    struct iphdr *ip_header;
    struct tcphdr *tcp_header;
    int lay4_len;
    int tcp_checksum = -1;
    int ret;

    struct sysflow_system_event *event = NULL;
    struct sysflow_action *action = NULL;

    eth_header = (struct ethhdr *)(skb_mac_header(skb));
    ip_header = (struct iphdr *)(skb_network_header(skb));
    tcp_header = (struct tcphdr *) (tcp_hdr(skb));
    lay4_len = skb->len - (ip_header->ihl << 2);

    if(S2OS_SYSFLOW_MOD_INIT == gStatus.sysflow_mode){
        event = (struct sysflow_system_event *)kmalloc(sizeof(struct sysflow_system_event), GFP_NOWAIT);
        printk("Get netfilter event start.\n");
        if(NULL != event){
            memset(event, 0, sizeof(struct sysflow_system_event));

            event->len = sizeof(struct sysflow_system_event);
            event->hdr = (struct sysflow_system_event_hdr *)kmalloc(sizeof(*(event->hdr)), GFP_NOWAIT);
            if(NULL != event->hdr){
                memset(event->hdr, 0, sizeof(struct sysflow_system_event_hdr));
                event->hdr->src_type = SYSFLOW_SRC_SOCKET;
                event->hdr->pid = current->pid;

                event->hdr->dst_type = SYSFLOW_DST_SOCKET;
                sprintf(event->hdr->dst_name, "'"NIPQUAD_FMT"'",NIPQUAD(ip_header->daddr));

                //event->hdr->fid.uuid = hash_uuid();
                //event->hdr->fid.inode_num = file;
                event->hdr->opcode = SYSFLOW_SOCKET_WRITE;
            } else {
                printk("[S2OS - nf_hooker] failed to alloc memory for event->hdr\n");
                goto ALLOW;
            }
        } else {
            /* TODO: handle memory allocation */
            printk("[S2OS - nf_hooker] failed to alloc memory for event\n");
            goto ALLOW;
        }

        printk("Get netfilter event.\n");
        printk("pid: %d", event->hdr->pid);

        action = (struct sysflow_action*)kmalloc(sizeof(*action), GFP_NOWAIT);
        memset(action, 0, sizeof(struct sysflow_action));
        if (NULL != action) {
            // call sysflow interface
            ret = s2os_invoke_sysflow_func((void*)(event), (void*)action);
        }

        printk("[S2os - nf_hooker] sysflow action ret: %d\n", ret);

        if(ret != SYSFLOW_ACTION_UNKNOWN && action){
            printk(KERN_INFO "[S2OS - nf_hooker] action->type: %d\n", action->action_type);
            switch (action->action_type) {
                case SYSFLOW_ACTION_ALLOW: {
                    goto ALLOW;
                }
                case SYSFLOW_ACTION_DENY: {
                    goto DENY;
                }
                case SYSFLOW_ACTION_REDIRECT: {
                    // TODO: redirect to another dst, change the dst IP & port num
                    goto ALLOW;
                }
                case SYSFLOW_ACTION_ENCODE:{
                    goto ALLOW;
                }
                case SYSFLOW_ACTION_DECODE:{
                    int oldtos = ip_header->tos;
                    // TODO: add the tag into ToS field of IP protocol
                    hdr_dump(eth_header);
                    
                    printk("[nf_hooker.c - SYSFLOW_ACTION_ENCODE] src IP:'"NIPQUAD_FMT"', dst IP:'"NIPQUAD_FMT"', tos: %x\n",
                            NIPQUAD(ip_header->saddr), NIPQUAD(ip_header->daddr), ip_header->tos);

                    // TODO: check the tos value with the context
                    goto ALLOW;
                }
                case SYSFLOW_ACTION_REPORT:{
                    struct utok_info ktou_act_report;
                    int msg_size;

                    ktou_act_report.header.type = SFP_ACTION_REPORT;
                    // FIXME: use a reasonable xid
                    ktou_act_report.header.xid = 0;
                    // header.len should be the size of a message except the header size
                    //ktou_act_report.header.len = sizeof(struct sfp_match) + 12 /*action_type+reason+data_len*/ + ktou_act_report.protocol.actreport.data_len;

                    // update header.len at the end
                    // fill out match
                    memset(&ktou_act_report.protocol.actreport.match, 0, sizeof(struct sfp_match)); 
                    // get action type from the flow entry
                    ktou_act_report.protocol.actreport.action_type = SYSFLOW_ACTION_REPORT;
                    // action report reason
                    ktou_act_report.protocol.actreport.reason = SYSFLOW_ACTION_REPORT_REASON_REPORT_TO_CONTROLLER | SYSFLOW_ACTION_REPORT_REASON_STRING_MESSAGE;
                    // set the corresponding reason data_len and data 

                    sprintf(ktou_act_report.protocol.actreport.data, "Alert! '"NIPQUAD_FMT"' is receving data from '"NIPQUAD_FMT"'\n",
                            NIPQUAD(ip_header->saddr), NIPQUAD(ip_header->daddr));

                    ktou_act_report.protocol.actreport.data_len = strlen(ktou_act_report.protocol.actreport.data);

                    // FIXME: calc header.len here for test
                    // header.len should be the size of a message except the header size
                    ktou_act_report.header.length = sizeof(struct sfp_match) + 12 /*action_type+reason+data_len*/ + ktou_act_report.protocol.actreport.data_len;

                    msg_size = sizeof(struct sfp_action_report);

                    printk(KERN_INFO "[SysFlow] action_report.reason msg_len: %d\n", msg_size);
                    printk(KERN_INFO "[SysFLow] Sending an action report: %s\n", ktou_act_report.protocol.actreport.data);

                    nl_send_action_report(&ktou_act_report, msg_size);
                    goto ALLOW;
                }
                case SYSFLOW_ACTION_QRAUNTINE:
                case SYSFLOW_ACTION_ISOLATION:
                case SYSFLOW_ACTION_MIGRATION:
                case SYSFLOW_ACTION_LOG:
                case SYSFLOW_ACTION_MESSAGE:
                case SYSFLOW_ACTION_NEXTMODULE:
                    printk(KERN_INFO "[S2OS - nf_hooker] Action not implemented yet.\n");
                default:
                    goto ALLOW;
            }
        }
    }


ALLOW:
    sweep_event(event);
    sweep_action(action);

    return NF_ACCEPT;

DENY:
    sweep_event(event);
    sweep_action(action);

    return NF_DROP;
}