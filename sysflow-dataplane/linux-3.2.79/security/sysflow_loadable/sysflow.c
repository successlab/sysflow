
#include <linux/jhash.h>
#include <linux/slab.h>
#include <linux/flex_array.h>
#include <linux/random.h>
#include <linux/rculist.h>
#include <linux/list.h>

//#include <linux/sysflow.h>
//#include <linux/sysflow_event.h>

#include "/home/haojin/sysflow/linux-3.2.0/include/linux/sysflow.h"
#include "/home/haojin/sysflow/linux-3.2.0/include/linux/sysflow_event.h"

#define MASK_ARRAY_SIZE_MIN 100
#define TBL_MIN_BUCKETS		256


#define _DBG 0

/*construct sysflow key for a system event*/
int sysflow_key_extract(struct sysflow_system_event* sse,
					struct sysflow_key *key){

	struct sysflow_system_event_hdr *header = sse->hdr;

	/*parse source from system event header*/
	if(header->src_type == SYSFLOW_SRC_UNKNOWN){
		return -1;
	}
	else if (header->src_type == SYSFLOW_SRC_PROCESS){
		key->pid = header->pid;
	}
	else{
		/*TODO: handle other source ids*/
	}
	
	/*parse destination from system event header*/
	if(header->dst_type == SYSFLOW_DST_UNKNOWN){
		return -1;
	}
	else if (header->dst_type == SYSFLOW_DST_FILE){
		key->fid = header->fid;
	}
	else{
		/*TODO: handle other destination ids*/
	}
	
	/*parse operation code from system event header*/
	key->opcode = header->opcode;
	if (unlikely(key->opcode == SYSFLOW_OP_UNKNOWN)){
		return -1;
	}

	return 0;
}

/*from hash value of masked key to find corresponding bucket*/
static struct hlist_head *find_bucket(struct table_instance *ti, u32 hash)
{
	hash = jhash_1word(hash, ti->hash_seed);
	return flex_array_get(ti->buckets,
				(hash & (ti->n_buckets - 1)));
}

/*
static uint16_t range_n_bytes(const struct sysflow_key_range *range)
{
	return range->end - range->start;
}
*/

static struct flex_array *alloc_buckets(unsigned int n_buckets)
{
	struct flex_array *buckets;
	int i, err;

	buckets = flex_array_alloc(sizeof(struct hlist_head *),
				   n_buckets, GFP_KERNEL);
	if (!buckets)
		return NULL;

	err = flex_array_prealloc(buckets, 0, n_buckets, GFP_KERNEL);
	if (err) {
		flex_array_free(buckets);
		return NULL;
	}

	for (i = 0; i < n_buckets; i++)
		INIT_HLIST_HEAD((struct hlist_head *)
					flex_array_get(buckets, i));

	return buckets;
}


/*compuate hash from sysflow key*/
/*
static uint32_t flow_hash(const struct sysflow_key *key,
		     uint32_t key_start, uint32_t key_end)
{
	//uint32_t key_start = range->start;
	//uint32_t key_end = range->end;
	const uint32_t *hash_key = (const uint32_t *)((const uint8_t *)key + key_start);
	uint32_t hash_u32s = (key_end - key_start) >> 2;
	//printk(KERN_INFO "before warning.\n");


	printk(KERN_INFO "before hasing. start: %d end: %d len: %u\n", key_start, key_end, hash_u32s);
	printk(KERN_INFO "key_srcid: %u, key_dstid: %u, key_op: %u", , key_end, hash_u32s);

	uint32_t hash = jhash2(hash_key, hash_u32s, 0);

	printk(KERN_INFO "hash: %u\n", hash);

	return hash;
}
*/

/*compuate hash from sysflow key*/
static uint32_t flow_hash(const struct sysflow_key *masked_key,
		     uint32_t key_mask)
{

	const uint32_t *hash_key = (const uint32_t *)(masked_key);

	uint32_t len = sizeof(struct sysflow_key) >> 2;

	
	//TODO: check if the key is correctly masked

	uint32_t hash = jhash2(hash_key, len, 0);

	if(_DBG){
		printk(KERN_INFO "----------------------------flow hash function----------------------------");
		printk(KERN_INFO "before hash: mask of key: %u, len of key: %u", key_mask, len);
		printk(KERN_INFO "masked key: pid: %u, fid-uuid: %u, fid-inode: %u, opcode: %u",
								 masked_key->pid, masked_key->fid.uuid, masked_key->fid.inode_num, masked_key->opcode);
		printk(KERN_INFO "hash: %u\n", hash);
		printk(KERN_INFO "-------------------------------------------------------------------------");
	}

	return hash;
}


/*create a new table instance*/
static struct table_instance *table_instance_alloc(int size)
{
	struct table_instance *ti = kmalloc(sizeof(*ti), GFP_KERNEL);

	if (!ti)
		return NULL;

	ti->buckets = alloc_buckets(size);

	if (!ti->buckets) {
		kfree(ti);
		return NULL;
	}
	ti->n_buckets = size;
	ti->node_ver = 0;
	ti->keep_flows = false;
	get_random_bytes(&ti->hash_seed, sizeof(uint32_t));

	return ti;
}



static struct mask_array *tbl_mask_array_alloc(int size)
{
	struct mask_array *new;
	int i;

	size = max(MASK_ARRAY_SIZE_MIN, size);
	new = kzalloc(sizeof(struct mask_array) +
		      sizeof(struct sysflow_mask *) * size, GFP_KERNEL);
	
	if (!new){ 
#if _DBG
		printk(KERN_INFO "[Sysflow] Can not allocate mask array.");
#endif
		return NULL;
	}

	new->count = 0;
	new->max = size;

	//explicitly nullify mask pointers
	for (i = 0; i < new->max; i++) {
		//if (ovsl_dereference(old->masks[i]))
		new->masks[i] = NULL;
	}
	return new;
}

static void free_buckets(struct flex_array *buckets)
{
	flex_array_free(buckets);
}


/*destroy an existing table instance*/
static void __table_instance_destroy(struct table_instance *ti)
{
	free_buckets(ti->buckets);
	kfree(ti);
}

/*initialize sysflow table*/
int sysflow_tbl_init(struct sysflow_table *table)
{
	struct table_instance *ti;
	struct mask_array *ma;

	if(!table){
		table = kmalloc(sizeof(struct sysflow_table), GFP_KERNEL);
	}

	ma = tbl_mask_array_alloc(MASK_ARRAY_SIZE_MIN);
	if (!ma)
		return -ENOMEM;

	ti = table_instance_alloc(TBL_MIN_BUCKETS);

	if (!ti)
		return -ENOMEM;

	//rcu_assign_pointer(table->ti, ti);
	//rcu_assign_pointer(table->mask_array, ma);

	table->ti = ti;
	table->mask_array = ma;
	table->count = 0;
	
	return 0;

/*
free_ti:
	__table_instance_destroy(ti);
	return -ENOMEM;
*/
}

static void table_instance_destroy(struct table_instance *ti,
				   bool deferred)
{
	int i;

	if (!ti)
		return;

	for (i = 0; i < ti->n_buckets; i++) {
		struct sysflow_entry *entry;
		struct hlist_head *head = flex_array_get(ti->buckets, i);
		struct hlist_node *n, *pos;
		int ver = ti->node_ver;

		hlist_for_each_entry_safe(entry, n, pos, head, sysflow_table.node[ver]) {
			hlist_del_rcu(&entry->sysflow_table.node[ver]);
			
			//TODO: free sysflow entry
			kfree(entry->mask);
			kfree(entry->actions);
			kfree(entry);
		}
	}

	__table_instance_destroy(ti);

}


static int tbl_mask_array_realloc(struct sysflow_table *tbl, int size)
{
	struct mask_array *old;
	struct mask_array *new;

	new = tbl_mask_array_alloc(size);
	if (!new)
		return -1;

	//old = ovsl_dereference(tbl->mask_array);
	old = tbl->mask_array;
	if (old) {
		int i, count = 0;

		for (i = 0; i < old->max; i++) {
			//if (ovsl_dereference(old->masks[i]))
			if(old->masks[i])
				new->masks[count++] = old->masks[i];
		}

		new->count = count;
	}
	//rcu_assign_pointer(tbl->mask_array, new);
	tbl->mask_array = new;

//	if (old)
//		call_rcu(&old->rcu, mask_array_rcu_cb);

	return 0;
}

/*add new sysflow entry into flow table instance*/
static void table_instance_insert(struct table_instance *ti,
				  struct sysflow_entry *entry)
{
	struct hlist_head *head;

	head = find_bucket(ti, entry->sysflow_table.hash);
	hlist_add_head_rcu(&entry->sysflow_table.node[ti->node_ver], head);
}

static bool mask_equal(const struct sysflow_mask *a,
		       const struct sysflow_mask *b)
{
	bool is_equal = (((a->key_mask)&7) == ((b->key_mask)&7));

	if(_DBG){
		printk(KERN_INFO "mask1: , mask2: , isEqual: ", a->key_mask, b->key_mask, (is_equal)?"true":"false");
	}

	return is_equal;
}

static bool *flow_mask_find(const struct sysflow_table *tbl,
					   const struct sysflow_mask *mask)
{
	struct mask_array *ma;
	int i;

	//ma = ovsl_dereference(tbl->mask_array);
	ma = tbl->mask_array;

	if(!tbl->mask_array || !ma){

#if _DBG
		printk(KERN_INFO "[Sysflow] Flow table mask array is null.");
#endif
	}

	for (i = 0; i < ma->max; i++) {
		struct sysflow_mask *t;

		//t = ovsl_dereference(ma->masks[i]);
		t = ma->masks[i];
		if (t && mask_equal(mask, t))
			return true;
	}

	return false;
}



/* Add 'mask' into the mask list, if it is not already there. */
static int mask_array_insert(struct sysflow_table *tbl, struct sysflow_entry  *entry)
{
	struct sysflow_mask *mask;

	//mask = flow_mask_find(tbl, new);

	mask = entry->mask;
	bool is_exist = flow_mask_find(tbl, mask);

	if (!is_exist) {
		struct mask_array *ma;
		struct sysflow_mask *new;
		int i;

		/* Allocate a new mask if none exsits. */
		new = kmalloc(sizeof(struct sysflow_mask), GFP_KERNEL);

		if (!new)
			return -1;

		new->key = mask->key;
		//new->range = mask->range;
		new->key_mask = mask->key_mask;

		/* Add mask to mask-list. */
		//ma = ovsl_dereference(tbl->mask_array);
		ma = tbl->mask_array;

		if (ma->count >= ma->max) {
			int err;

			err = tbl_mask_array_realloc(tbl, ma->max +
							  MASK_ARRAY_SIZE_MIN);
			if (err) {
				kfree(new);
				return err;
			}
			//ma = ovsl_dereference(tbl->mask_array);
			ma = tbl->mask_array;
		}

		for (i = 0; i < ma->max; i++) {
			struct sysflow_mask *t;

			//t = ovsl_dereference(ma->masks[i]);
			t = ma->masks[i];

			if (!t) {
				//rcu_assign_pointer(ma->masks[i], mask);
				ma->masks[i] = new;
				ma->count++;
				break;
			}
		}

	} 

	return 0;
}

/*compute the masked key*/
void sysflow_mask_key(struct sysflow_key *dst, const struct sysflow_key *src,
		       bool full, const struct sysflow_mask *mask)
{
	if(!dst){
		dst = kmalloc(sizeof(struct sysflow_key), GFP_KERNEL);
	}

	*dst = *src;

	uint8_t *b = (const uint8_t *)(dst);
	
	int size_src = KEY_SRC_SIZE;	//size of src id in key
	int size_dst = KEY_DST_SIZE;	//size of dst id in key
	int size_opcode = sizeof(src->opcode); //size of opcode id in key
	int i;

	if(!(mask->key_mask & 1)){	// src id of key is not masked
		for(i = 0; i < size_src; i++){
			b[i] &= 0;
		}
	}
	if(!(mask->key_mask & 2)){  // dst id of key is not masked
		for(i = size_src; i < (size_src + size_dst); i++){
			b[i] &= 0;
		}
	}
	if(!(mask->key_mask & 4)){	// opcode of key is not masked
		for(i = (size_src + size_dst); 
					i < (size_src + size_dst + size_opcode); i++){
			b[i] &= 0;
		}
	}

	if(_DBG){
		printk(KERN_INFO "--------sysflow mask key function--------------------------");
		printk(KERN_INFO "mask: %u\n", mask->key_mask % 8);
		printk(KERN_INFO "raw key: pid: %u, fid-uuid: %u, fid-inode: %u, opcode: %u", src->pid, src->fid.uuid, src->fid.inode_num, src->opcode);
		printk(KERN_INFO "masked key: pid: %u, fid-uuid: %u, fid-inode: %u, opcode: %u", dst->pid, dst->fid.uuid, dst->fid.inode_num, dst->opcode);
		printk(KERN_INFO "-------------------------------------------------------------");
	}
}

int sysflow_tbl_insert(struct sysflow_table *table, struct sysflow_entry *entry){
	
	struct table_instance *ti;

	if(!table || !entry){
		return -1;
	}

	ti = table->ti;

	if(!ti){
		return -1;
	}

	mask_array_insert(table, entry);

	struct sysflow_mask *mask = entry->mask;

	//printk(KERN_INFO "In Insert: start:%u, end:%u\n", mask->range.start, mask->range.end);
#if _DBG
	printk(KERN_INFO "In Insert: key mask: %u\n", mask->key_mask);
#endif
	struct sysflow_key *masked_key = kmalloc(sizeof(struct sysflow_key), GFP_KERNEL);
	sysflow_mask_key(masked_key, &entry->key, false, mask); /// &entry->key -> masked_key
	entry->sysflow_table.hash = flow_hash(masked_key, mask->key_mask);

	table_instance_insert(ti, entry);

	return 0;
}

int sysflow_tbl_remove(struct sysflow_table *table, struct sysflow_entry *entry){
	struct table_instance *ti;

//	ti = ovsl_dereference(table->ti);
	ti = table->ti;

	if(!ti){
		return -1;
	}

	/*remove flow entry from hash list*/
	hlist_del_rcu(&entry->sysflow_table.node[ti->node_ver]);

	/*remove from mask array*/
	struct sysflow_mask *mask;
	mask = entry->mask;

	if (mask) {
			struct mask_array *ma;
			int i;
			
			ma = table->mask_array;
			
			/* Remove the deleted mask pointers from the array */
			for (i = 0; i < ma->max; i++) {
				if (mask == ma->masks[i]) {
					ma->masks[i] = NULL;
					break;
				}
			}

			/* Shrink the mask array if necessary. */
			if (ma->max >= (MASK_ARRAY_SIZE_MIN * 2) &&
			    ma->count <= (ma->max / 3))
				tbl_mask_array_realloc(table, ma->max / 2);
	}

	/*TODO: add cleanup functions*/
	kfree(entry->mask);
	kfree(entry->actions);
	kfree(entry);

	return 0;

}

static int sysflow_flow_entry_insert(struct sysflow_table *table,
				  struct sysflow_entry *entry){

	struct hlist_head *head;
	struct table_instance *ti;
	struct mask_array *ma;
	struct sysflow_mask *mask;


	int i;

	mask = entry->mask;

	ti = table->ti;
	if(!ti){
		return -1;
	}
	ma = table->mask_array;
	if(!ma){
		return -1;
	}

	/* insert mask into mask array */
	for (i = 0; i < ma->max; i++) {
		struct sysflow_mask *t;

		t = ma->masks[i];
		if (t && mask_equal(mask, t)){ //Found mask in mask array
			return 1;
		}
	}
	
	//insert flow key into flow table
	head = find_bucket(ti, entry->sysflow_table.hash);
	hlist_add_head_rcu(&entry->sysflow_table.node[ti->node_ver], head);

	return;
}

static bool cmp_key(const struct sysflow_key *key1,
		    const struct sysflow_key *key2)
{
	const uint32_t *cp1 = (const uint32_t *)(key1);
	const uint32_t *cp2 = (const uint32_t *)(key2);
	long diffs = 0;
	int size = sizeof(struct sysflow_key);
	int i;

	for (i = 0; i < sizeof(struct sysflow_key);  i += sizeof(uint32_t))
		diffs |= *cp1++ ^ *cp2++;

	return diffs == 0;
}

static bool flow_cmp_masked_key(const struct sysflow_entry *entry,
				const struct sysflow_key *key)
{
	return cmp_key(&entry->key, key);
}

/* find matched sysflow entry based on key from a system event */
static struct sysflow_entry *masked_flow_lookup(struct table_instance *ti,  
					const struct sysflow_key *key,
					const struct sysflow_mask *mask){

	struct sysflow_entry *flow_entry;
	struct hlist_head *head;
	struct hlist_node *n;
	uint32_t hash;
	struct sysflow_key *masked_key = kmalloc(sizeof(struct sysflow_key), GFP_KERNEL);

	sysflow_mask_key(masked_key, key, false, mask); /// key -> masked_key
	hash = flow_hash(masked_key, mask->key_mask); ///masked key -> hash
	head = find_bucket(ti, hash); ///hash -> bucket

#if _DBG
	printk(KERN_INFO "in masked_flow_lookup: event hash value is: %u\n", hash);
#endif

	if(!head){
#if _DBG
		printk(KERN_INFO "in masked_flow_lookup: head is null.\n");
#endif
	}

	hlist_for_each_entry_rcu(flow_entry, n, head, sysflow_table.node[ti->node_ver]) 
	{ /// list
#if _DBG
		printk(KERN_INFO "in masked_flow_lookup: flow_entry hash: %u\n", flow_entry->sysflow_table.hash);
		printk(KERN_INFO "in masked_flow_lookup: flow_entry key pid: %u\n", flow_entry->key.pid);
		printk(KERN_INFO "in masked_flow_lookup: flow_entry action type: %u\n", flow_entry->actions->action_type);
#endif
		/*	
		if (flow_entry->mask == mask && flow_entry->sysflow_table.hash == hash &&
		    flow_cmp_masked_key(flow_entry, masked_key)) ///compare key
			return flow_entry;
		*/
		if (flow_entry->sysflow_table.hash == hash)
			return flow_entry;
	}

	return NULL;
}

struct sysflow_entry *sysflow_tbl_lookup(struct sysflow_table *table,
				    const struct sysflow_key *key){

	struct sysflow_entry *flow_entry;

	struct table_instance *ti;
	struct mask_array *ma;
	int i;


	ti = table->ti;
	if(!ti){
		return NULL;
	}

	ma = table->mask_array;
	if(!ma){
		return NULL;
	}

	for (i = 0; i < ma->max; i++)  {
		struct sysflow_mask *mask = ma->masks[i];
		
		if(!mask){
			continue;
		}

#if _DBG
		printk(KERN_INFO "In sysflow_tbl_look_up: key mask: %u\n", mask->key_mask);
#endif
		flow_entry = masked_flow_lookup(ti, key, mask);
		if (flow_entry) { /* Found */
			return flow_entry;
		}
	}	

	return NULL;
}

void sysflow_tbl_destroy(struct sysflow_table *table)
{

	if(!table){
		return;
	}

	if(table->ti){
		table_instance_destroy(table->ti, false);
	}

	if(table->mask_array){
		kfree(table->mask_array);
	}

	kfree(table);

	/*
	struct table_instance *ti = rcu_dereference_raw(table->ti);
//	free_percpu(table->mask_cache);
//	kfree(rcu_dereference_raw(table->mask_array));
	table_instance_destroy(ti, false);
	*/
}
