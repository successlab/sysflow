#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/gfp.h>
#include <asm/current.h>

#include <linux/sysflow.h>
#include <linux/sysflow_event.h>
#include <linux/protocol.h>

struct datapath {
    //  struct rcu_head rcu;
    // struct list_head list_node;

    /* Flow table. */
    struct sysflow_table *table;
};

static struct datapath *gDp;

extern inline int s2os_invoke_sysflow_func(void* pData, void* retData);
extern void nl_send_action_report(struct utok_info* actreport, int msg_size);
extern unsigned int byte4toi(unsigned char* p, unsigned int n);