#ifndef FLOW_NETLINK_H
#define FLOW_NETLINK_H 1

/*definition of sysflow flow generic netlink family*/

/* attribute type of sysflow flow*/
enum sysflow_flow_attr {
    SYSFLOW_FLOW_ATTR_UNSPEC,
    SYSFLOW_FLOW_ATTR_KEY,      /*nested key_attr*/
    SYSFLOW_FLOW_ATTR_MASK,      /*u32 of key mask*/
    SYSFLOW_FLOW_ATTR_ACTION,   /*nested action-attr*/
    SYSFLOW_FLOW_ATTR_STATUS,    
    __SYSFLOW_FLOW_ATTR_MAX,
};

#define SYSFLOW_FLOW_ATTR_MAX (__SYSFLOW_FLOW_ATTR_MAX - 1)

/* sysflow flow attribute policy */
static struct nla_policy flow_policy = [SYSFLOW_ATTR_MAX + 1] = {
    [SYSFLOW_FLOW_ATTR_KEY] = { .type = NLA_NESTED },
    [SYSFLOW_FLOW_ATTR_MASK] = { .type = NLA_U32},
    [SYSFLOW_FLOW_ATTR_ACTION] = { .type = NLA_NESTED },
    [SYSFLOW_FLOW_ATTR_STATUS] = { .type = NLA_NESTED },
};

static const struct genl_ops sysflow_flow_genl_ops[] = {
    { .cmd = SYSFLOW_FLOW_CMD_NEW,
      .flags = GENL_ADMIN_PERM, /* Requires CAP_NET_ADMIN privilege. */
      .policy = flow_policy,
      .doit = sysflow_flow_cmd_new
    },
    { .cmd = SYSFLOW_FLOW_CMD_DEL,
      .flags = GENL_ADMIN_PERM, /* Requires CAP_NET_ADMIN privilege. */
      .policy = flow_policy,
      .doit = sysflow_flow_cmd_del
    },
};


struct sysflow_flow_status{
    int hit_count;
    //TODO: extensible metadata
};

static struct genl_family sysflow_flow_genl_family = {
    .id = GENL_ID_GENERATE,
    .hdrsize = 0,
    .name = SYSFLOW_FLOW_FAMILY,
    .version = SYSFLOW_VERSION,
    .maxattr = SYSFLOW_FLOW_ATTR_MAX,
    .netnsok = true,
    .parallel_ops = true,
    .ops = sysflow_flow_genl_ops,
    .n_ops = ARRAY_SIZE(sysflow_flow_genl_ops),
}
/*end definition of sysflow flow generic netlink family*/

/*key attributes for generic netlink
can extend more source or detination IDs by adding more key attributes?
*/
enum sysflow_key_attr {
	SYSFLOW_KEY_ATTR_UNSPEC,
	SYSFLOW_KEY_ATTR_PID,	/*U32*/
	SYSFLOW_KEY_ATTR_FID,	/*nested fid_attr*/
	SYSFLOW_KEY_ATTR_OPCODE, /*U32*/
	__SYSFLOW_KEY_ATTR_MAX
};

#define SYSFLOW_KEY_ATTR_MAX (__SYSFLOW_KEY_ATTR_MAX - 1)

/*file id attributes for generic netlink*/
enum sysflow_fid_attr {
	SYSFLOW_FID_ATTR_UNSPEC,
	SYSFLOW_FID_ATTR_UUID,	/*U32*/
	SYSFLOW_FID_ATTR_INODE,  /*U32*/
	__SYSFLOW_FID_ATTR_MAX
};

#define SYSFLOW_FID_ATTR_MAX (__SYSFLOW_FID_ATTR_MAX - 1)

/*action attributes for generic netlink*/
enum sysflow_action_attr {
	SYSFLOW_ACTION_ATTR_UNSPEC,
	SYSFLOW_ACTION_ATTR_TYPE,	/*U32*/
	SYSFLOW_ACTION_ATTR_LEN, 	/*U32*/
	SYSFLOW_ACTION_ATTR_DATA, 	/**/
	__SYSFLOW_ACTION_ATTR_MAX
};

#define SYSFLOW_ACTION_ATTR_MAX (__SYSFLOW_ACTION_ATTR_MAX - 1)

/*put sysflow key to output buffer*/
int sysflow_put_flow_key(const struct sysflow_key *key, struct sk_buff *skb);
/*put sysflow mask to output buffer*/
int sysflow_put_flow_mask(const struct sysflow_mask *mask, struct sk_buff *skb);
/*put sysflow actions to output buffer*/
int sysflow_put_flow_actions(const struct sysflow_action *action, struct sk_buff *skb);


/*extract sysflow key and mask into sysflow entry*/
int sysflow_get_flow_key_mask(struct sysflow_entry *entry, 
						const struct nlattr *nla_key, const struct nlattr *nla_mask);
/*extract sysflow actions into sysflow entry*/
int sysflow_get_flow_actions(struct sysflow_entry *entry, const struct nlattr *nla_actions);
/*extract sysflow key into sysflow entry*/
int sysflow_get_flow_key(struct sysflow_entry *entry, struct sysflow_key key);
/*extract sysflow mask into sysflow entry*/
int sysflow_get_flow_mask(struct sysflow_entry *entry, struct sysflow_mask *mask)


//TODO: add metadata processing

#endif /*flow_netlink.h*/