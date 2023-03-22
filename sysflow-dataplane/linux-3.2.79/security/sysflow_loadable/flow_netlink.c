#include "flow_netlink.h"
#include "sysflow.h"

/*extract nested flow key attributes*/
static int parse_flow_key_attrs(const struct nlattr *attr,
				const struct nlattr *a[])
{
	const struct nlattr *nla;
	int rem;

	nla_for_each_nested(nla, attr, rem) {
		uint16_t type = nla_type(nla);

		if (type > SYSFLOW_KEY_ATTR_MAX) {
			return -1;
		}
			a[type] = nla;
		}
	}
	return 0;
}

/*extract nested flow fid attributes*/
static int parse_fid_attributes(const struct nlattr *attr, struct file_id *fid){
	struct file_id fid;
	const struct nlattr *nla;
	int rem;

	if(!attr){
		return -1;
	}

	nla_for_each_nested(nla, attr, rem) {
		uint16_t type = nla_type(nla);

		if (type > SYSFLOW_FID_ATTR_MAX) {
			return -1;
		}
	
		if(type == SYSFLOW_FID_UUID){
			fid->uuid = nla_get_be32(nla_data(nla));
		}

		if(type == SYSFLOW_FID_INODE){
			fid->inode_num = nla_get_be32(nla_data(nla));
		}

	}

	return 0;
}

/*extract sysflow key into sysflow entry*/
int sysflow_get_flow_key(struct sysflow_entry *entry, struct sysflow_key key){
	if(!entry){
		return -1;
	}

	if(!key){
		return -1;
	}

	entry->key = key;

	return 0;

}

/*extract sysflow mask into sysflow entry*/
int sysflow_get_flow_mask(struct sysflow_entry *entry, struct sysflow_mask *mask){
	if(!entry){
		return -1;
	}

	if(!mask){
		return -1;
	}

	entry->mask = mask;

	return 0;
}

/**/
static int sysflow_set_extact_mask(struct sysflow_mask *mask, struct sysflow_key key){
	if(!mask){
		mask = kmalloc(sizeof(struct sysflow_mask), GFP_KERNEL);
	}

	mask->key = key;
	mask->key_mask = 0x7;

	return 0;
}

/*extract sysflow key and mask into sysflow entry*/
int sysflow_get_flow_key_mask(struct sysflow_entry *entry, const struct nlattr *nla_key, const struct nlattr *nla_mask){
	const struct nlattr *attrs[OVS_KEY_ATTR_MAX + 1];
	struct sysflow_key key;
	struct sysflow_mask *mask = kmalloc(sizeof(struct sysflow_mask), GFP_KERNEL);
	struct file_id *fid = kmalloc(sizeof(struct file_id), GFP_KERNEL);
	int ret;

	if(!entry){
		return -1;
	}

	/*parse nested key attributes*/
	ret = parse_flow_key_attrs(nla_key, attrs);

	/*make sure src id is not empty*/
	if(!attrs[SYSFLOW_KEY_PID]){
		return -1;
	}

	/*make sure dst id is not empty*/
	if(!attrs[SYSFLOW_KEY_FID]){
		return -1;
	}

	/*make sure opcode is not empty*/
	if(!attrs[SYSFLOW_KEY_OPCODE]){
		return -1;
	}

	ret = parse_fid_attributes(attrs[SYSFLOW_KEY_FID], fid);
	if (ret == -1){
		return -1;
	}
	
	key.pid = nla_get_be32(attrs[SYSFLOW_KEY_PID]);
	key.fid = *fid;
	key.opcode = nla_get_be32(attrs[SYSFLOW_KEY_OPCODE]);
	
	entry->key = key;

	
	if(!nla_mask){	/*if the mask filed is missing, set the exact match*/
		sysflow_set_extact_mask(mask, key);
	}
	else{	/*parse mask from flow attribute*/
		mask->key = key;
		mask->key_mask = nla_get_be32(nla_mask);
	}

	entry->mask = mask;

	return 0;
}

/*extract sysflow actions into sysflow entry*/
int sysflow_get_flow_actions(struct sysflow_entry *entry, const struct nlattr *nla_actions){
	
}
