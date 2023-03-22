/*
* A Very LSM implementation 
*/
#include <linux/time.h>
#include <linux/version.h>  /* for check kernel version */
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/ptrace.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/security.h> /* for lsm and sysflow security module */
#include <linux/xattr.h>
#include <linux/capability.h>
#include <linux/unistd.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#include <linux/swap.h>
#include <linux/spinlock.h>
#include <linux/syscalls.h>
#include <linux/file.h>
#include <linux/namei.h>
#include <linux/mount.h>
#include <linux/ext2_fs.h>
#include <linux/proc_fs.h>
#include <linux/fs.h>
#include <linux/kd.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/tty.h>
#include <linux/stat.h>
#include <net/icmp.h>
#include <net/ip.h>		/* for sysctl_local_port_range[] */
#include <net/tcp.h>		/* struct or_callable used in sock_rcv_skb */
#include <asm/uaccess.h>
#include <asm/ioctls.h>
#include <linux/bitops.h>
#include <linux/interrupt.h>
#include <linux/netdevice.h>	/* for network interface checks */
#include <linux/netlink.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/quota.h>
#include <linux/un.h>		/* for Unix socket types */
#include <net/af_unix.h>	/* for Unix socket types */
#include <linux/parser.h>
#include <linux/nfs_mount.h>
#include <net/ipv6.h>
#include <linux/hugetlb.h>
#include <linux/personality.h>
#include <linux/sysctl.h>
#include <linux/audit.h>
#include <linux/string.h>

#include <linux/sysflow.h> /* for sysflow types */
#include <linux/sysflow_event.h>
#include <linux/protocol.h>

//#define IF_DEBUG_SAMPLE

//haojin: hashtable functions:
#define HT_MINIMUM_CAPACITY 8
#define HT_LOAD_FACTOR 5
#define HT_MINIMUM_THRESHOLD (HT_MINIMUM_CAPACITY) * (HT_LOAD_FACTOR)

#define HT_GROWTH_FACTOR 2
#define HT_SHRINK_THRESHOLD (1 / 4)

#define HT_ERROR -1
#define HT_SUCCESS 0

#define HT_UPDATED 1
#define HT_INSERTED 0

#define HT_NOT_FOUND 0
#define HT_FOUND 01

#define HT_INITIALIZER {0, 0, 0, 0, 0, NULL, NULL, NULL};

typedef int (*comparison_t)(void*, void*, size_t);
typedef size_t (*hash_t)(void*, size_t);

/****************** STRUCTURES ******************/

typedef struct HTNode {
	struct HTNode* next;
	void* key;
	void* value;

} HTNode;

typedef struct HashTable {
	size_t size;
	size_t threshold;
	size_t capacity;

	size_t key_size;
	size_t value_size;

	comparison_t compare;
	hash_t hash;

	HTNode** nodes;

} HashTable;

/* Setup */
int ht_setup(HashTable* table,
						 size_t key_size,
						 size_t value_size,
						 size_t capacity);

int ht_copy(HashTable* first, HashTable* second);
int ht_move(HashTable* first, HashTable* second);
int ht_swap(HashTable* first, HashTable* second);

/* Destructor */
int ht_destroy(HashTable* table);

int ht_insert(HashTable* table, void* key, void* value);

int ht_contains(HashTable* table, void* key);
void* ht_lookup(HashTable* table, void* key);
const void* ht_const_lookup(const HashTable* table, void* key);

#define HT_LOOKUP_AS(type, table_pointer, key_pointer) \
	(*(type*)ht_lookup((table_pointer), (key_pointer)))

int ht_erase(HashTable* table, void* key);
int ht_clear(HashTable* table);

int ht_is_empty(HashTable* table);
bool ht_is_initialized(HashTable* table);

int ht_reserve(HashTable* table, size_t minimum_capacity);

/****************** PRIVATE ******************/

void _ht_int_swap(size_t* first, size_t* second);
void _ht_pointer_swap(void** first, void** second);

size_t _ht_default_hash(void* key, size_t key_size);
int _ht_default_compare(void* first_key, void* second_key, size_t key_size);

size_t _ht_hash(const HashTable* table, void* key);
bool _ht_equal(const HashTable* table, void* first_key, void* second_key);

bool _ht_should_grow(HashTable* table);
bool _ht_should_shrink(HashTable* table);

HTNode* _ht_create_node(HashTable* table, void* key, void* value, HTNode* next);
int _ht_push_front(HashTable* table, size_t index, void* key, void* value);
void _ht_destroy_node(HTNode* node);

int _ht_adjust_capacity(HashTable* table);
int _ht_allocate(HashTable* table, size_t capacity);
int _ht_resize(HashTable* table, size_t new_capacity);
void _ht_rehash(HashTable* table, HTNode** old, size_t old_capacity);



int ht_setup(HashTable* table,
						 size_t key_size,
						 size_t value_size,
						 size_t capacity) {
	if (table == NULL) return HT_ERROR;

	if (capacity < HT_MINIMUM_CAPACITY) {
		capacity = HT_MINIMUM_CAPACITY;
	}

	if (_ht_allocate(table, capacity) == HT_ERROR) {
		return HT_ERROR;
	}

	table->key_size = key_size;
	table->value_size = value_size;
	table->hash = _ht_default_hash;
	table->compare = _ht_default_compare;
	table->size = 0;

	return HT_SUCCESS;
}

int ht_copy(HashTable* first, HashTable* second) {
    size_t chain;
	HTNode* node;


	if (first == NULL) return HT_ERROR;
	if (!ht_is_initialized(second)) return HT_ERROR;

	if (_ht_allocate(first, second->capacity) == HT_ERROR) {
		return HT_ERROR;
	}

	first->key_size = second->key_size;
	first->value_size = second->value_size;
	first->hash = second->hash;
	first->compare = second->compare;
	first->size = second->size;

	for (chain = 0; chain < second->capacity; ++chain) {
		for (node = second->nodes[chain]; node; node = node->next) {
			if (_ht_push_front(first, chain, node->key, node->value) == HT_ERROR) {
				return HT_ERROR;
			}
		}
	}
	return HT_SUCCESS;
}

int ht_move(HashTable* first, HashTable* second) {
	if (first == NULL) return HT_ERROR;
	if (!ht_is_initialized(second)) return HT_ERROR;

	*first = *second;
	second->nodes = NULL;
	return HT_SUCCESS;
}

int ht_swap(HashTable* first, HashTable* second) {
	if (!ht_is_initialized(first)) return HT_ERROR;
	if (!ht_is_initialized(second)) return HT_ERROR;

	_ht_int_swap(&first->key_size, &second->key_size);
	_ht_int_swap(&first->value_size, &second->value_size);
	_ht_int_swap(&first->size, &second->size);
	_ht_pointer_swap((void**)&first->hash, (void**)&second->hash);
	_ht_pointer_swap((void**)&first->compare, (void**)&second->compare);
	_ht_pointer_swap((void**)&first->nodes, (void**)&second->nodes);
	return HT_SUCCESS;
}

int ht_destroy(HashTable* table) {
    HTNode* node;
	HTNode* next;
	size_t chain;

	
	if (!ht_is_initialized(table)) return HT_ERROR;

	for (chain = 0; chain < table->capacity; ++chain) {
		node = table->nodes[chain];
		while (node) {
			next = node->next;
			_ht_destroy_node(node);
			node = next;
		}
	}

	kfree(table->nodes);
	return HT_SUCCESS;
}

int ht_insert(HashTable* table, void* key, void* value) {
	size_t index;
	HTNode* node;

	if (!ht_is_initialized(table)) return HT_ERROR;
	if (key == NULL) return HT_ERROR;

	if (_ht_should_grow(table)) {
		_ht_adjust_capacity(table);
	}

	index = _ht_hash(table, key);
	for (node = table->nodes[index]; node; node = node->next) {
		if (_ht_equal(table, key, node->key)) {
			memcpy(node->value, value, table->value_size);
			return HT_UPDATED;
		}
	}

	if (_ht_push_front(table, index, key, value) == HT_ERROR) {
		return HT_ERROR;
	}

	++table->size;

	return HT_INSERTED;
}

int ht_contains(HashTable* table, void* key) {
	size_t index;
	HTNode* node;

	if (!ht_is_initialized(table)) return HT_ERROR;
	if (key == NULL) return HT_ERROR;

	index = _ht_hash(table, key);
	for (node = table->nodes[index]; node; node = node->next) {
		if (_ht_equal(table, key, node->key)) {
			return HT_FOUND;
		}
	}

	return HT_NOT_FOUND;
}

void* ht_lookup(HashTable* table, void* key) {
	HTNode* node;
	size_t index;

	if (table == NULL) return NULL;
	if (key == NULL) return NULL;

	index = _ht_hash(table, key);
	for (node = table->nodes[index]; node; node = node->next) {
		if (_ht_equal(table, key, node->key)) {
			return node->value;
		}
	}

	return NULL;
}

const void* ht_const_lookup(const HashTable* table, void* key) {
	const HTNode* node;
	size_t index;


	if (table == NULL) return NULL;
	if (key == NULL) return NULL;

	index = _ht_hash(table, key);
	for (node = table->nodes[index]; node; node = node->next) {
		if (_ht_equal(table, key, node->key)) {
			return node->value;
		}
	}

	return NULL;
}

int ht_erase(HashTable* table, void* key) {
	HTNode* node;
	HTNode* previous;
	size_t index;

	if (table == NULL) return HT_ERROR;
	if (key == NULL) return HT_ERROR;

	index = _ht_hash(table, key);
	node = table->nodes[index];

	for (previous = NULL; node; previous = node, node = node->next) {
		if (_ht_equal(table, key, node->key)) {
			if (previous) {
				previous->next = node->next;
			} else {
				table->nodes[index] = node->next;
			}

			_ht_destroy_node(node);
			--table->size;

			if (_ht_should_shrink(table)) {
				if (_ht_adjust_capacity(table) == HT_ERROR) {
					return HT_ERROR;
				}
			}

			return HT_SUCCESS;
		}
	}

	return HT_NOT_FOUND;
}

int ht_clear(HashTable* table) {

	if (table == NULL) return HT_ERROR;
	if (table->nodes == NULL) return HT_ERROR;

	ht_destroy(table);
	_ht_allocate(table, HT_MINIMUM_CAPACITY);
	table->size = 0;

	return HT_SUCCESS;
}

int ht_is_empty(HashTable* table) {
	if (table == NULL) return HT_ERROR;
	return table->size == 0;
}

bool ht_is_initialized(HashTable* table) {
	return table != NULL && table->nodes != NULL;
}

int ht_reserve(HashTable* table, size_t minimum_capacity) {
	if (!ht_is_initialized(table)) return HT_ERROR;

	/*
	 * We expect the "minimum capacity" to be in elements, not in array indices.
	 * This encapsulates the design.
	 */
	if (minimum_capacity > table->threshold) {
		return _ht_resize(table, minimum_capacity / HT_LOAD_FACTOR);
	}

	return HT_SUCCESS;
}

/****************** PRIVATE ******************/

void _ht_int_swap(size_t* first, size_t* second) {
	size_t temp = *first;
	*first = *second;
	*second = temp;
}

void _ht_pointer_swap(void** first, void** second) {
	void* temp = *first;
	*first = *second;
	*second = temp;
}

int _ht_default_compare(void* first_key, void* second_key, size_t key_size) {
	return memcmp(first_key, second_key, key_size);
}

size_t _ht_default_hash(void* raw_key, size_t key_size) {
	// djb2 string hashing algorithm
	// sstp://www.cse.yorku.ca/~oz/hash.ssml
	size_t byte;
	size_t hash = 5381;
	char* key = raw_key;

	for (byte = 0; byte < key_size; ++byte) {
		// (hash << 5) + hash = hash * 33
		hash = ((hash << 5) + hash) ^ key[byte];
	}

	return hash;
}

size_t _ht_hash(const HashTable* table, void* key) {
#ifdef HT_USING_POWER_OF_TWO
	return table->hash(key, table->key_size) & table->capacity;
#else
	return table->hash(key, table->key_size) % table->capacity;
#endif
}

bool _ht_equal(const HashTable* table, void* first_key, void* second_key) {
	return table->compare(first_key, second_key, table->key_size) == 0;
}

bool _ht_should_grow(HashTable* table) {
	if(table->size <= table->capacity){
	    return table->size == table->capacity;
    }
}

bool _ht_should_shrink(HashTable* table) {
	if(table->size <= table->capacity) {
	    return table->size == table->capacity * HT_SHRINK_THRESHOLD;
    }
}

HTNode*
_ht_create_node(HashTable* table, void* key, void* value, HTNode* next) {
	HTNode* node;

	if(table != NULL && key != NULL && value != NULL){

	    if ((node = kmalloc(sizeof *node, GFP_ATOMIC)) == NULL) {
		    return NULL;
	    }
	    if ((node->key = kmalloc(table->key_size, GFP_ATOMIC)) == NULL) {
		    return NULL;
	    }
	    if ((node->value = kmalloc(table->value_size, GFP_ATOMIC)) == NULL) {
		    return NULL;
	    }

	    memcpy(node->key, key, table->key_size);
	    memcpy(node->value, value, table->value_size);
	    node->next = next;

	    return node;
    } else {
        return NULL;
    }
}

int _ht_push_front(HashTable* table, size_t index, void* key, void* value) {
	table->nodes[index] = _ht_create_node(table, key, value, table->nodes[index]);
	return table->nodes[index] == NULL ? HT_ERROR : HT_SUCCESS;
}

void _ht_destroy_node(HTNode* node) {
	if(node != NULL){

	kfree(node->key);
	kfree(node->value);
	kfree(node);
    }
}

int _ht_adjust_capacity(HashTable* table) {
	return _ht_resize(table, table->size * HT_GROWTH_FACTOR);
}

int _ht_allocate(HashTable* table, size_t capacity) {
	if ((table->nodes = kmalloc(capacity * sizeof(HTNode*), GFP_ATOMIC)) == NULL) {
		return HT_ERROR;
	}
	memset(table->nodes, 0, capacity * sizeof(HTNode*));

	table->capacity = capacity;
	table->threshold = capacity * HT_LOAD_FACTOR;

	return HT_SUCCESS;
}

int _ht_resize(HashTable* table, size_t new_capacity) {
	HTNode** old;
	size_t old_capacity;

	if (new_capacity < HT_MINIMUM_CAPACITY) {
		if (table->capacity > HT_MINIMUM_CAPACITY) {
			new_capacity = HT_MINIMUM_CAPACITY;
		} else {
			/* NO-OP */
			return HT_SUCCESS;
		}
	}

	old = table->nodes;
	old_capacity = table->capacity;
	if (_ht_allocate(table, new_capacity) == HT_ERROR) {
		return HT_ERROR;
	}

	_ht_rehash(table, old, old_capacity);

	kfree(old);

	return HT_SUCCESS;
}

void _ht_rehash(HashTable* table, HTNode** old, size_t old_capacity) {
	HTNode* node;
	HTNode* next;
	size_t new_index;
	size_t chain;

	for (chain = 0; chain < old_capacity; ++chain) {
		for (node = old[chain]; node;) {
			next = node->next;

			new_index = _ht_hash(table, node->key);
			node->next = table->nodes[new_index];
			table->nodes[new_index] = node;

			node = next;
		}
	}
}
//end





#define NIPQUAD(addr) \
        ((unsigned char *)&addr)[0], \
    ((unsigned char *)&addr)[1], \
    ((unsigned char *)&addr)[2], \
    ((unsigned char *)&addr)[3]
#define NIPQUAD_FMT "%u.%u.%u.%u"

static unsigned long long count = 0;

#define EVALUATE_PERFORMANCE 0
#define SAMPLE_DBG 0

#if EVALUATE_PERFORMANCE
static long old_counter, new_counter;
static struct timespec old_time, new_time;
#endif 

MODULE_LICENSE("GPL");

// used to store global function pointers of sysflow
struct s2os_sysflow_func_struct gSysflowFunc;
EXPORT_SYMBOL(gSysflowFunc);
// used to store global funtion pointers of LSM 
struct s2os_lsm_func_struct gLsmFunc;
EXPORT_SYMBOL(gLsmFunc);
// used to store global status shared by LSM and sysflow. 
struct s2os_global_status_struct gStatus;
EXPORT_SYMBOL(gStatus);

#define S2OS_MAX_PROC_NAME 16   // see sched.h, TASK_COMM_LEN
#define S2OS_MAX_FILE_NAME 255  // see limits.h
struct timeval start_time, stop_time;
unsigned int t;


// File operation
#define S2OS_FILE_OP_WRITE          2
#define S2OS_FILE_OP_READ           4

HashTable table;

//======================================

/**
 * Init S2OS
 **/
void s2os_init(void)
{
    int i, key, value;
#if EVALUATE_PERFORMANCE
    old_counter = 0;
    getnstimeofday(&old_time);
#endif
    /* will be assigned by loadable sysflow table module */
    gSysflowFunc.call_sysflow = NULL;

    /* init module modes */
	gStatus.lsm_mode = S2OS_LSM_MOD_INIT;
    // sysflow is not ready at this time. 
	gStatus.sysflow_mode = S2OS_SYSFLOW_MOD_NULL;

    //Create a hash table for test
	/* Choose initial capacity of 10 */
	/* Specify the size of the keys and values you want to store once */
	ht_setup(&table, sizeof(int), sizeof(int), 200);

	//ht_reserve(&table, 100);

    printk(KERN_INFO "[sysflow debug]init sysflow module in sample.c\n");    

    for (key = 0, value = 1; key <= 200; ++key, ++value) {
		if(ht_insert(&table, &key, &value) != HT_INSERTED){
            printk(KERN_INFO "ht_insert error\n");    
        }
	}


}

/**
 *
 * Will be called by sysflow table module to register 
 * its callback function. 
 *
 **/
int s2os_save_sysflow_func(S2OS_SYSFLOW_FUNC pFunc)
{
    if(pFunc != NULL){
        gSysflowFunc.call_sysflow = pFunc;

        printk(KERN_INFO "[S2OS] LSM: the sysflow function pointer is saved in LSM\n");
        return 0;   // succeed
    }

    return -1;  // fail
}
// use this such that other GPL modules can access this function
EXPORT_SYMBOL(s2os_save_sysflow_func);

int s2os_rm_sysflow_func(){
    gSysflowFunc.call_sysflow = NULL;

    // wait for the execution of last event
    printk(KERN_INFO "[S2OS] LSM: Sysflow table remove its function pointer in LSM\n");
    return 0;
}
EXPORT_SYMBOL(s2os_rm_sysflow_func);

int s2os_save_report_func(S2OS_REPORT_FUNC pFunc){
    if(pFunc != NULL){
        gSysflowFunc.call_report = pFunc;

        printk(KERN_INFO "[S2OS] the report function pointer is saved in LSM\n");
        return 0;   // succeed
    }

    return -1;  // fail
}
// use this such that other GPL modules can access this function
EXPORT_SYMBOL(s2os_save_report_func);

int s2os_rm_report_func(){
    gSysflowFunc.call_report = NULL;

    // wait for the execution of last event
    printk(KERN_INFO "[S2OS] LSM:  remove its function pointer in LSM\n");
    return 0;
}
EXPORT_SYMBOL(s2os_rm_report_func);

/**
 * Sysflow table call this function to send data to LSM 
 * Not used now. 
 * 
 **/
int s2os_inovke_lsm_func(void* pData)
{
    if(pData != NULL){
        // Todo:  
		// process pData here ... 
#if SAMPLE_DBG
        printk(KERN_INFO "[S2OS] LSM: sysflow table invoke LSM, state:%d\n", gStatus.lsm_mode);
#endif
        return 0;   // succeed
    }
    return -1;  // fail
}
// use this such that other GPL modules can access this function
EXPORT_SYMBOL(s2os_inovke_lsm_func);



/**
 * LSM calls this function to send data to sysflow table module
 * 
 * Todo: implement meaningful things later
 * 
 **/
inline int s2os_invoke_sysflow_func(void* pData, void* retData)
{
    int ret;
    if(pData != NULL){
        if(gSysflowFunc.call_sysflow != NULL){
			// Just call sysflow table interface. 
            
            ret = gSysflowFunc.call_sysflow(pData, retData);
#ifdef IF_DEBUG_SAMPLE
            //printk(KERN_INFO "[S2OS] LSM: LSM invoke sysflow, sysflow returned: %d\n", ret);
            //printk(KERN_INFO "[S2OS] LSM: action is: %d\n", ((struct sysflow_action*)retData)->action_type);
            printk(KERN_INFO "[S2OS] LSM: invoking!");
#endif
            return ((struct sysflow_action*)retData)->action_type;
        }
    }
    return SYSFLOW_ACTION_UNKNOWN;  // fail
}
EXPORT_SYMBOL(s2os_invoke_sysflow_func);

int s2os_invoke_report_func(struct utok_info* actreport, int msg_size){
	if(gSysflowFunc.call_report != NULL){
		gSysflowFunc.call_report(actreport, msg_size);
		return 0;
	}
	else{
		return -1;
	}
}
EXPORT_SYMBOL(s2os_invoke_report_func);


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
#if SAMPLE_DBG
    print_hex_dump_bytes("", DUMP_PREFIX_NONE, s_uuid, 16);
#endif
    return ret;
}


/**
 * This implements the hook for file permision checking. 
 * The file structure is available here and mask is available. 
 * This hook construct an @event and send the event to sysflow table
 * by callying gSysflowFunc.call_sysflow(). 
 * 
 * When the sysflow table returns, this procedure determines to 
 * deny, block or redirect the operation.
 * 
 * 
 * deny: 		just return -EACCES
 * allow: 		just return 0
 * redirect: 	may modify something or pass the decision along until sometime 
 * 				it's appropriate to modify something. 
 * 				Usually, we will modify the file descripter table
 *  			to return a decoy file's descripter. 
 * 
 * Todo: 		check source code to decide how to implement redirect
 *
 **/
static int s2os_file_permission(struct file *file, int mask)
{
    
    int ret;
    struct sysflow_system_event *event = NULL;
    struct sysflow_action *action = NULL;
    char* buffer, *dirpath;

	char ac_Buf[64];
	char * pc_FdName = NULL;

#if 0
    const char* fname = (file->f_path.dentry)->d_name.name; 
    if ( 0 != strncmp(fname, "you-cant-write", 14) && 
         0 != strncmp(fname, "you-cant-read", 13)) {
        return 0;
    }
#endif

    // for debug purpose
    // Because every printk will case a 'write' to a file, we can't use
    // any printk in the routine. 
    // But for debug purpose, we need to dump some info, so we need 
    // to sypecify some files. Only for the specified files, will we 
    // generate events. 
    // Here we hard code /home/hongda/Downloads/TEST/ 
    // Any files under the above path will be applied to the sysflow rules.  
    
    buffer = (char*)__get_free_page(GFP_KERNEL);
    dirpath = dentry_path_raw(file->f_path.dentry, buffer, PAGE_SIZE); 
    if (IS_ERR(dirpath)) {
#if SAMPLE_DBG
        printk(KERN_ALERT "[S2OS] LSM: invalid dirpath: %s\n", dirpath);
#endif
        goto ALLOW;
    }
    if ( 0 != strncmp(dirpath, "/tmp/monitored/", 15) ) {
        goto ALLOW;
    }
#if SAMPLE_DBG
    printk(KERN_ALERT "[S2OS] LSM: dirpath: %s\n", dirpath);
#endif


    if(S2OS_SYSFLOW_MOD_INIT == gStatus.sysflow_mode){
        // Todo:  choose a better flag. */
        event  = (struct sysflow_system_event*)kmalloc(sizeof(*event), GFP_KERNEL);
        if (NULL != event) {
            event->len = sizeof(struct sysflow_system_event); 
            event->hdr = (struct sysflow_system_event_hdr*)kmalloc(sizeof(*(event->hdr)), GFP_KERNEL);
			memset(event->hdr, 0, sizeof(struct sysflow_system_event_hdr));
            if (NULL != event->hdr) {
                event->hdr->src_type = SYSFLOW_SRC_PROCESS;
                event->hdr->dst_type = SYSFLOW_DST_FILE;
                event->hdr->pid = current->pid;
                event->hdr->fid.uuid = 0;//hash_uuid(file->f_path.dentry->d_inode->i_sb->s_uuid);
                event->hdr->fid.inode_num = file->f_path.dentry->d_inode->i_ino;
				printk("[S2OS - sample.c] inode_num: %d, uuid: %d\n", event->hdr->fid.inode_num, event->hdr->fid.uuid);

				pc_FdName = d_path(&(file->f_path), ac_Buf, sizeof(ac_Buf));

				if (NULL != pc_FdName){
					printk("[S2OS - sample.c] filename: %s\n", pc_FdName);
				}
				else{
					printk("[S2OS - sample.c] filename: NULL\n");
				}
				
                switch (mask) {
                    // write
                    case 2: {
                        event->hdr->opcode = SYSFLOW_FILE_WRITE;
						printk("[S2OS - sample.c] trying to write to file \n");
                        break;
                    }
                    // read
                    case 4: {
                        event->hdr->opcode = SYSFLOW_FILE_READ;
						printk("[S2OS - sample.c] trying to read to file\n");
                        break;
                    }
                    default:{
                        // event->hdr->opcode = SYSFLOW_OP_UNKNOWN;
						printk("[S2OS - sample.c] trying to unknown to file\n");
                        event->hdr->opcode = SYSFLOW_FILE_READ;
					}
                }
            } else {
                // TODO: handle memory allocation. 
                printk("[s2os_file_permission] failed to alloc memory for event->hdr\n");
            }
        } else {
            /* TODO: handle memory allocation */
            printk("[s2os_file_permission] failed to alloc memory for event\n");
        }
        // allocate action
        action = (struct sysflow_action*)kmalloc(sizeof(*action), GFP_KERNEL);
		memset(action, 0, sizeof(*action));
        if (NULL != action) {
            // call sysflow interface
            ret = s2os_invoke_sysflow_func((void*)(event), (void*)action);

            if(action){
                printk(KERN_INFO "[s2os_file_permission] action->type: %d\n", action->action_type);
                switch (action->action_type) {
                    case SYSFLOW_ACTION_ALLOW: {
                        goto ALLOW;
                    }
                    case SYSFLOW_ACTION_DENY: {
                        goto DENY;
                    }
                    case SYSFLOW_ACTION_REDIRECT: {
						char * decoy_file = NULL;
						struct file *decoy_fp = NULL;
						struct file *old_fp = NULL;
						
						// old_fp = (struct file *)kmalloc(sizeof(struct file), GFP_KERNEL);
						// memcpy(old_fp, file, sizeof(struct file));

						decoy_file = (char *)kmalloc(action->len+1, GFP_KERNEL);
						memcpy(decoy_file, action->action_code, action->len);
						decoy_file[action->len] = '\0';

						printk("[s2os_file_permission] decoy_file: %s\n", decoy_file);
						printk("[s2os_file_permission] decoy_fp: %p", decoy_fp);

						decoy_fp = filp_open(decoy_file, file->f_flags, file->f_mode);

						memcpy(file, decoy_fp, sizeof(struct file));
						
						// FIXME: find a way to close current file pointer
						// filp_close(old_fp, NULL);

                        goto ALLOW;
                    }
                    case SYSFLOW_ACTION_ISOLATION:{
						// maintain a list to store all the resources that has been accessed by other processed
						goto ALLOW;
					}
                    case SYSFLOW_ACTION_REPORT:{
						struct utok_info ktou_act_report;
						int msg_size;

						//memcpy(&ktou_act_report.header, &info->header, sizeof(struct sfp_header));
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
						ktou_act_report.protocol.actreport.reason = SYSFLOW_ACTION_REPORT_REASON_REPORT_TO_CONTROLLER | SYSFLOW_ACTION_REPORT_REASON_ALERT_TO_USER | SYSFLOW_ACTION_REPORT_REASON_STRING_MESSAGE;
						// set the corresponding reason data_len and data 

						sprintf(ktou_act_report.protocol.actreport.data, "Alert! Process %d is trying to access file %s with mask %d\n",
								current->pid, pc_FdName, mask);

						ktou_act_report.protocol.actreport.data_len = strlen(ktou_act_report.protocol.actreport.data);

						// FIXME: calc header.len here for test
						// header.len should be the size of a message except the header size
						ktou_act_report.header.length = sizeof(struct sfp_match) + 12 /*action_type+reason+data_len*/ + ktou_act_report.protocol.actreport.data_len;

						msg_size = sizeof(struct sfp_action_report);

						printk(KERN_INFO "[SysFlow] action_report.reason msg_len: %d\n", msg_size);
						printk(KERN_INFO "[SysFLow] Sending an action report: %s\n", ktou_act_report.protocol.actreport.data);

						s2os_invoke_report_func(&ktou_act_report, msg_size);
					}
					case SYSFLOW_ACTION_QRAUNTINE:
                    case SYSFLOW_ACTION_MESSAGE:
					case SYSFLOW_ACTION_ENCODE:
                    case SYSFLOW_ACTION_DECODE:
                    case SYSFLOW_ACTION_LOG:
                    case SYSFLOW_ACTION_NEXTMODULE:
                        printk(KERN_INFO "[S2OS] LSM: Action not implemented yet.\n");
                    default:
                        goto ALLOW;
                }
            }   
        }
    }

ALLOW: 
    sweep_event(event);
    sweep_action(action);
    free_page((unsigned long)buffer);

    return 0;
DENY:
    sweep_event(event);
    sweep_action(action);
    free_page((unsigned long)buffer);
    return -EACCES;
}

static int s2os_ptrace_access_check(struct task_struct *child,
				     unsigned int mode)
{
	return 0;
}

static int s2os_ptrace_traceme(struct task_struct *parent)
{
	return 0;
}

static int s2os_capget(struct task_struct *target, kernel_cap_t *effective,
			  kernel_cap_t *inheritable, kernel_cap_t *permitted)
{
	return 0;
}

static int s2os_capset(struct cred *new, const struct cred *old,
			  const kernel_cap_t *effective,
			  const kernel_cap_t *inheritable,
			  const kernel_cap_t *permitted)
{
	return 0;
}

//static int s2os_capable(struct task_struct *tsk, const struct cred *cred,
			   //struct user_namespace *ns, int cap, int audit)
static	int s2os_capable(const struct cred *cred, struct user_namespace *ns,
			int cap, int audit)
{
	return 0;
}

static int s2os_quotactl(int cmds, int type, int id, struct super_block *sb)
{
	return 0;
}

static int s2os_quota_on(struct dentry *dentry)
{
	return 0;
}

static int s2os_syslog(int type)
{
	return 0;
}


static int s2os_vm_enough_memory(struct mm_struct *mm, long pages)
{
	return 0;
}

/* binprm security operations */

static int s2os_bprm_set_creds(struct linux_binprm *bprm)
{
	return 0;
}

static int s2os_bprm_secureexec(struct linux_binprm *bprm)
{
	return 0;
}

static void s2os_bprm_committing_creds(struct linux_binprm *bprm)
{
	
}

static void s2os_bprm_committed_creds(struct linux_binprm *bprm)
{
	
}

static int s2os_sb_alloc_security(struct super_block *sb)
{
	return 0;
}

static void s2os_sb_free_security(struct super_block *sb)
{

}

static int s2os_sb_copy_data(char *orig, char *copy)
{
	return 0;
}

static int s2os_sb_remount(struct super_block *sb, void *data)
{
	return 0;
}

static int s2os_sb_kern_mount(struct super_block *sb, int flags, void *data)
{
	return 0;
}

static int s2os_sb_statfs(struct dentry *dentry)
{
	return 0;
}

static int s2os_mount(char *dev_name, struct path *path, char *type, unsigned long flags, void *data)
{
	return 0;
}

static int s2os_umount(struct vfsmount *mnt, int flags)
{
	return 0;
}


/* inode security operations */

static int s2os_inode_alloc_security(struct inode *inode)
{
	return 0;
}

static void s2os_inode_free_security(struct inode *inode)
{

}

static int s2os_inode_init_security(struct inode *inode, struct inode *dir,
				       const struct qstr *qstr, char **name,
				       void **value, size_t *len)
{
	return 0;
}

static int s2os_inode_create(struct inode *dir, struct dentry *dentry, int mask)
{
// 	int ret;
// 	struct sysflow_system_event *event = NULL; 
// 	struct sysflow_action *action = NULL;
//     if(S2OS_SYSFLOW_MOD_INIT == gStatus.sysflow_mode){
//         /* Todo:  choose a better flag. */
//         event  = (struct sysflow_system_event*)kmalloc(sizeof(*event), GFP_KERNEL);
//         if (NULL != event) {
//             event->len = sizeof(struct sysflow_system_event); 
//             event->hdr = (struct sysflow_system_event_hdr*)kmalloc(sizeof(*(event->hdr)), GFP_KERNEL);
//             if (NULL != event->hdr) {
//                 event->hdr->src_type = SYSFLOW_SRC_PROCESS;
//                 event->hdr->dst_type = SYSFLOW_DST_FILE;
//                 event->hdr->pid = current->pid;
//                 event->hdr->fid.uuid = hash_uuid(dir->i_sb->s_uuid);
//                 event->hdr->fid.inode_num = dir->i_ino;
// 				event->hdr->opcode = SYSFLOW_INODE_CREATE;
// 			} else {
// 				// TODO: handle memory allocation error. 
// 			}
// 		} else {
// 			// TODO: handle memory allocation error. 
// 		} 
// #if SAMPLE_DBG 
//         printk(KERN_ALERT "[S2OS] LSM: %s is called\n", __FUNCTION__);
// #endif

//         action = (struct sysflow_action*)kmalloc(sizeof(*action), GFP_KERNEL);
// 		if (NULL != action) {
//             ret = s2os_invoke_sysflow_func((void*)(event), (void*)action);
// 			// TODO: set action fields in to a global variable. 
// 		}

// 	}

	return 0;
}

static int s2os_inode_link(struct dentry *old_dentry, struct inode *dir, struct dentry *new_dentry)
{
// 	int ret;
// 	struct sysflow_system_event *event = NULL; 
// 	struct sysflow_action *action = NULL;
//     if(S2OS_SYSFLOW_MOD_INIT == gStatus.sysflow_mode){
//         /* Todo:  choose a better flag. */
//         event  = (struct sysflow_system_event*)kmalloc(sizeof(*event), GFP_KERNEL);
//         if (NULL != event) {
//             event->len = sizeof(struct sysflow_system_event); 
//             event->hdr = (struct sysflow_system_event_hdr*)kmalloc(sizeof(*(event->hdr)), GFP_KERNEL);
//             if (NULL != event->hdr) {
//                 event->hdr->src_type = SYSFLOW_SRC_PROCESS;
//                 event->hdr->dst_type = SYSFLOW_DST_FILE;
//                 event->hdr->pid = current->pid;
//                 event->hdr->fid.uuid = hash_uuid(old_dentry->d_inode->i_sb->s_uuid);
//                 event->hdr->fid.inode_num = old_dentry->d_inode->i_ino;
// 				event->hdr->opcode = SYSFLOW_LINK_CREATE;
// 			} else {
// 				// TODO: handle memory allocation error. 
// 			}
// 		} else {
// 			// TODO: handle memory allocation error. 
// 		} 
// #if SAMPLE_DBG 
//         printk(KERN_ALERT "[S2OS] LSM: %s is called\n", __FUNCTION__);
// #endif

//         action = (struct sysflow_action*)kmalloc(sizeof(*action), GFP_KERNEL);
// 		if (NULL != action) {
//             ret = s2os_invoke_sysflow_func((void*)(event), (void*)action);
// 			// TODO: set action fields in to a global variable. 
// 		}

// 	}

	return 0;
}

static int s2os_inode_unlink(struct inode *dir, struct dentry *dentry)
{
// 	int ret;
// 	struct sysflow_system_event *event = NULL; 
// 	struct sysflow_action *action = NULL;
//     if(S2OS_SYSFLOW_MOD_INIT == gStatus.sysflow_mode){
//         /* Todo:  choose a better flag. */
//         event  = (struct sysflow_system_event*)kmalloc(sizeof(*event), GFP_KERNEL);
//         if (NULL != event) {
//             event->len = sizeof(struct sysflow_system_event); 
//             event->hdr = (struct sysflow_system_event_hdr*)kmalloc(sizeof(*(event->hdr)), GFP_KERNEL);
//             if (NULL != event->hdr) {
//                 event->hdr->src_type = SYSFLOW_SRC_PROCESS;
//                 event->hdr->dst_type = SYSFLOW_DST_FILE;
//                 event->hdr->pid = current->pid;
//                 event->hdr->fid.uuid = hash_uuid(dentry->d_inode->i_sb->s_uuid);
//                 event->hdr->fid.inode_num = dentry->d_inode->i_ino;
// 				event->hdr->opcode = SYSFLOW_UNLINK;
// 			} else {
// 				// TODO: handle memory allocation error. 
// 			}
// 		} else {
// 			// TODO: handle memory allocation error. 
// 		} 

// #if SAMPLE_DBG 
//         printk(KERN_ALERT "[S2OS] LSM: %s is called\n", __FUNCTION__);
// #endif
//         action = (struct sysflow_action*)kmalloc(sizeof(*action), GFP_KERNEL);
// 		if (NULL != action) {
//             ret = s2os_invoke_sysflow_func((void*)(event), (void*)action);
// 			// TODO: set action fields in to a global variable. 
// 		}

// 	}

	return 0;

}

static int s2os_inode_symlink(struct inode *dir, struct dentry *dentry, const char *name)
{
// 	int ret;
// 	struct sysflow_system_event *event = NULL; 
// 	struct sysflow_action *action = NULL;
//     if(S2OS_SYSFLOW_MOD_INIT == gStatus.sysflow_mode){
//         /* Todo:  choose a better flag. */
//         event  = (struct sysflow_system_event*)kmalloc(sizeof(*event), GFP_KERNEL);
//         if (NULL != event) {
//             event->len = sizeof(struct sysflow_system_event); 
//             event->hdr = (struct sysflow_system_event_hdr*)kmalloc(sizeof(*(event->hdr)), GFP_KERNEL);
//             if (NULL != event->hdr) {
//                 event->hdr->src_type = SYSFLOW_SRC_PROCESS;
//                 event->hdr->dst_type = SYSFLOW_DST_FILE;
//                 event->hdr->pid = current->pid;
//                 event->hdr->fid.uuid = hash_uuid(dir->i_sb->s_uuid);
//                 event->hdr->fid.inode_num = dir->i_ino;
// 				event->hdr->opcode = SYSFLOW_SYMLINK_CREATE;
// 			} else {
// 				// TODO: handle memory allocation error. 
// 			}
// 		} else {
// 			// TODO: handle memory allocation error. 
// 		} 

// #if SAMPLE_DBG 
//         printk(KERN_ALERT "[S2OS] LSM: %s is called\n", __FUNCTION__);
// #endif
//         action = (struct sysflow_action*)kmalloc(sizeof(*action), GFP_KERNEL);
// 		if (NULL != action) {
//             ret = s2os_invoke_sysflow_func((void*)(event), (void*)action);
// 			// TODO: set action fields in to a global variable. 
// 		}

// 	}

	return 0;
}

static int s2os_inode_mkdir(struct inode *dir, struct dentry *dentry, int mask)
{
// 	int ret;
// 	struct sysflow_system_event *event = NULL; 
// 	struct sysflow_action *action = NULL;
//     if(S2OS_SYSFLOW_MOD_INIT == gStatus.sysflow_mode){
//         /* Todo:  choose a better flag. */
//         event  = (struct sysflow_system_event*)kmalloc(sizeof(*event), GFP_KERNEL);
//         if (NULL != event) {
//             event->len = sizeof(struct sysflow_system_event); 
//             event->hdr = (struct sysflow_system_event_hdr*)kmalloc(sizeof(*(event->hdr)), GFP_KERNEL);
//             if (NULL != event->hdr) {
//                 event->hdr->src_type = SYSFLOW_SRC_PROCESS;
//                 event->hdr->dst_type = SYSFLOW_DST_FILE;
//                 event->hdr->pid = current->pid;
//                 event->hdr->fid.uuid = hash_uuid(dir->i_sb->s_uuid);
//                 event->hdr->fid.inode_num = dir->i_ino;
// 				event->hdr->opcode = SYSFLOW_DIR_CREATE;
// 			} else {
// 				// TODO: handle memory allocation error. 
// 			}
// 		} else {
// 			// TODO: handle memory allocation error. 
// 		} 
// #if SAMPLE_DBG 
//         printk(KERN_ALERT "[S2OS] LSM: %s is called\n", __FUNCTION__);
// #endif

//         action = (struct sysflow_action*)kmalloc(sizeof(*action), GFP_KERNEL);
// 		if (NULL != action) {
//             ret = s2os_invoke_sysflow_func((void*)(event), (void*)action);
// 			// TODO: set action fields in to a global variable. 
// 		}

// 	}

	return 0;
}

static int s2os_inode_rmdir(struct inode *dir, struct dentry *dentry)
{
// 	int ret;
// 	struct sysflow_system_event *event = NULL; 
// 	struct sysflow_action *action = NULL;
//     if(S2OS_SYSFLOW_MOD_INIT == gStatus.sysflow_mode){
//         /* Todo:  choose a better flag. */
//         event  = (struct sysflow_system_event*)kmalloc(sizeof(*event), GFP_KERNEL);
//         if (NULL != event) {
//             event->len = sizeof(struct sysflow_system_event); 
//             event->hdr = (struct sysflow_system_event_hdr*)kmalloc(sizeof(*(event->hdr)), GFP_KERNEL);
//             if (NULL != event->hdr) {
//                 event->hdr->src_type = SYSFLOW_SRC_PROCESS;
//                 event->hdr->dst_type = SYSFLOW_DST_FILE;
//                 event->hdr->pid = current->pid;
//                 event->hdr->fid.uuid = hash_uuid(dentry->d_inode->i_sb->s_uuid);
//                 event->hdr->fid.inode_num = dentry->d_inode->i_ino;
// 				event->hdr->opcode = SYSFLOW_DIR_REMOVE;
// 			} else {
// 				// TODO: handle memory allocation error. 
// 			}
// 		} else {
// 			// TODO: handle memory allocation error. 
// 		} 
// #if SAMPLE_DBG 
//         printk(KERN_ALERT "[S2OS] LSM: %s is called\n", __FUNCTION__);
// #endif

//         action = (struct sysflow_action*)kmalloc(sizeof(*action), GFP_KERNEL);
// 		if (NULL != action) {
//             ret = s2os_invoke_sysflow_func((void*)(event), (void*)action);
// 			// TODO: set action fields in to a global variable. 
// 		}

// 	}

	return 0;
}

static int s2os_inode_mknod(struct inode *dir, struct dentry *dentry, int mode, dev_t dev)
{
// 	int ret;
// 	struct sysflow_system_event *event = NULL; 
// 	struct sysflow_action *action = NULL;
//     if(S2OS_SYSFLOW_MOD_INIT == gStatus.sysflow_mode){
//         /* Todo:  choose a better flag. */
//         event  = (struct sysflow_system_event*)kmalloc(sizeof(*event), GFP_KERNEL);
//         if (NULL != event) {
//             event->len = sizeof(struct sysflow_system_event); 
//             event->hdr = (struct sysflow_system_event_hdr*)kmalloc(sizeof(*(event->hdr)), GFP_KERNEL);
//             if (NULL != event->hdr) {
//                 event->hdr->src_type = SYSFLOW_SRC_PROCESS;
//                 event->hdr->dst_type = SYSFLOW_DST_FILE;
//                 event->hdr->pid = current->pid;
//                 event->hdr->fid.uuid = hash_uuid(dir->i_sb->s_uuid);
//                 event->hdr->fid.inode_num = dir->i_ino;
// 				event->hdr->opcode = SYSFLOW_DEV_INODE_CREATE;
// 			} else {
// 				// TODO: handle memory allocation error. 
// 			}
// 		} else {
// 			// TODO: handle memory allocation error. 
// 		} 
// #if SAMPLE_DBG 
//         printk(KERN_ALERT "[S2OS] LSM: %s is called\n", __FUNCTION__);
// #endif

//         action = (struct sysflow_action*)kmalloc(sizeof(*action), GFP_KERNEL);
// 		if (NULL != action) {
//             ret = s2os_invoke_sysflow_func((void*)(event), (void*)action);
// 			// TODO: set action fields in to a global variable. 
// 		}

// 	}

	return 0;
}

static int s2os_inode_rename(struct inode *old_inode, struct dentry *old_dentry,
				struct inode *new_inode, struct dentry *new_dentry)
{
// 	int ret;
// 	struct sysflow_system_event *event = NULL; 
// 	struct sysflow_action *action = NULL;
//     if(S2OS_SYSFLOW_MOD_INIT == gStatus.sysflow_mode){
//         /* Todo:  choose a better flag. */
//         event  = (struct sysflow_system_event*)kmalloc(sizeof(*event), GFP_KERNEL);
//         if (NULL != event) {
//             event->len = sizeof(struct sysflow_system_event); 
//             event->hdr = (struct sysflow_system_event_hdr*)kmalloc(sizeof(*(event->hdr)), GFP_KERNEL);
//             if (NULL != event->hdr) {
//                 event->hdr->src_type = SYSFLOW_SRC_PROCESS;
//                 event->hdr->dst_type = SYSFLOW_DST_FILE;
//                 event->hdr->pid = current->pid;
//                 event->hdr->fid.uuid = hash_uuid(old_dentry->d_inode->i_sb->s_uuid);
//                 event->hdr->fid.inode_num = old_dentry->d_inode->i_ino;
// 				event->hdr->opcode = SYSFLOW_DEV_INODE_CREATE;
// 			} else {
// 				// TODO: handle memory allocation error. 
// 			}
// 		} else {
// 			// TODO: handle memory allocation error. 
// 		} 
// #if SAMPLE_DBG 
//         printk(KERN_ALERT "[S2OS] LSM: %s is called\n", __FUNCTION__);
// #endif

//         action = (struct sysflow_action*)kmalloc(sizeof(*action), GFP_KERNEL);
// 		if (NULL != action) {
//             ret = s2os_invoke_sysflow_func((void*)(event), (void*)action);
// 			// TODO: set action fields in to a global variable. 
// 		}

// 	}

	return 0;

}
static int s2os_inode_readlink(struct dentry *dentry)
{
	return 0;
}

static int s2os_inode_follow_link(struct dentry *dentry, struct nameidata *nameidata)
{
	return 0;
}

//static int s2os_inode_permission(struct inode *inode, int mask, unsigned flags)
static int s2os_inode_permission(struct inode *inode, int mask)
{
	return 0;
}

static void s2os_sb_clone_mnt_opts(const struct super_block *oldsb,
					struct super_block *newsb)
{

}

static int s2os_file_set_fowner(struct file *file)
{
	return 0;
}

static int s2os_parse_opts_str(char *options, struct security_mnt_opts *opts)
{
    return 0;
}

static int s2os_inode_setattr(struct dentry *dentry, struct iattr *iattr)
{
	return 0;
}

static int s2os_inode_getattr(struct vfsmount *mnt, struct dentry *dentry)
{
	return 0;
}
/*
static int s2os_inode_setotherxattr(struct dentry *dentry, const char *name)
{
	return 0;
}
*/
static int s2os_inode_setxattr(struct dentry *dentry, const char *name,
				  const void *value, size_t size, int flags)
{
	return 0;
}

static void s2os_inode_post_setxattr(struct dentry *dentry, const char *name,
					const void *value, size_t size,
					int flags)
{
	
}

static int s2os_inode_getxattr(struct dentry *dentry, const char *name)
{
	return 0;
}

static int s2os_inode_listxattr(struct dentry *dentry)
{
	return 0;
}

static int s2os_inode_removexattr(struct dentry *dentry, const char *name)
{
	return 0;
}

static int s2os_inode_getsecurity(const struct inode *inode, const char *name, void **buffer, bool alloc)
{
	return 0;
}

static int s2os_inode_setsecurity(struct inode *inode, const char *name,
				     const void *value, size_t size, int flags)
{
	return 0;
}

static int s2os_inode_listsecurity(struct inode *inode, char *buffer, size_t buffer_size)
{
	return 0;
}

static void s2os_inode_getsecid(const struct inode *inode, u32 *secid)
{
	
}


/* file security operations */
/*
static int s2os_revalidate_file_permission(struct file *file, int mask)
{
	return 0;
}
*/

/*
static int s2os_file_permission(struct file *file, int mask)
{
	return 0;
}
*/
static int s2os_file_alloc_security(struct file *file)
{
	return 0;
}

static void s2os_file_free_security(struct file *file)
{

}

static int s2os_file_ioctl(struct file *file, unsigned int cmd,
			      unsigned long arg)
{
// 	int ret;
// 	struct sysflow_system_event *event = NULL; 
// 	struct sysflow_action *action = NULL;
//     if(S2OS_SYSFLOW_MOD_INIT == gStatus.sysflow_mode){
//         /* Todo:  choose a better flag. */
//         event  = (struct sysflow_system_event*)kmalloc(sizeof(*event), GFP_KERNEL);
//         if (NULL != event) {
//             event->len = sizeof(struct sysflow_system_event); 
//             event->hdr = (struct sysflow_system_event_hdr*)kmalloc(sizeof(*(event->hdr)), GFP_KERNEL);
//             if (NULL != event->hdr) {
//                 event->hdr->src_type = SYSFLOW_SRC_PROCESS;
//                 event->hdr->dst_type = SYSFLOW_DST_FILE;
//                 event->hdr->pid = current->pid;
//                 event->hdr->fid.uuid = hash_uuid(file->f_path.dentry->d_inode->i_sb->s_uuid);
//                 event->hdr->fid.inode_num = file->f_path.dentry->d_inode->i_ino;
// 				event->hdr->opcode = SYSFLOW_FILE_IOCTL;
// 			} else {
// 				// TODO: handle memory allocation error. 
// 			}
// 		} else {
// 			// TODO: handle memory allocation error. 
// 		} 
// #if SAMPLE_DBG 
//         printk(KERN_ALERT "[S2OS] LSM: %s is called\n", __FUNCTION__);
// #endif

//         action = (struct sysflow_action*)kmalloc(sizeof(*action), GFP_KERNEL);
// 		if (NULL != action) {
//             ret = s2os_invoke_sysflow_func((void*)(event), (void*)action);
// 			// TODO: set action fields in to a global variable. 
// 		}

// 	}

	return 0;

}

static int s2os_file_mmap(struct file *file, unsigned long reqprot,
			     unsigned long prot, unsigned long flags,
			     unsigned long addr, unsigned long addr_only)
{
	return 0;
}

static int s2os_file_mprotect(struct vm_area_struct *vma,
				 unsigned long reqprot,
				 unsigned long prot)
{
	return 0;
}

static int s2os_file_lock(struct file *file, unsigned int cmd)
{
	return 0;
}

static int s2os_file_fcntl(struct file *file, unsigned int cmd,
			      unsigned long arg)
{
	return 0;
}

static int s2os_file_send_sigiotask(struct task_struct *tsk,
				       struct fown_struct *fown, int signum)
{
	return 0;
}

static int s2os_file_receive(struct file *file)
{
	return 0;
}

static int s2os_dentry_open(struct file *file, const struct cred *cred)
{
	return 0;
}


/* task security operations */

static int s2os_task_create(unsigned long clone_flags)
{
	//printk("[+s2os_take_create]: call task_create() count=%llu\n", ++count);
	return 0;
}

static int s2os_cred_alloc_blank(struct cred *cred, gfp_t gfp)
{
	return 0;
}

static void s2os_cred_free(struct cred *cred)
{
	
}

static int s2os_cred_prepare(struct cred *new, const struct cred *old,
				gfp_t gfp)
{
	return 0;
}

static void s2os_cred_transfer(struct cred *new, const struct cred *old)
{

}

static int s2os_kernel_act_as(struct cred *new, u32 secid)
{
	return 0;
}

static int s2os_kernel_create_files_as(struct cred *new, struct inode *inode)
{
	return 0;
}

static int s2os_kernel_module_request(char *kmod_name)
{
	return 0;
}

static int s2os_task_setpgid(struct task_struct *p, pid_t pgid)
{
	return 0;
}

static int s2os_task_getpgid(struct task_struct *p)
{
	return 0;
}

static int s2os_task_getsid(struct task_struct *p)
{
	return 0;
}

static void s2os_task_getsecid(struct task_struct *p, u32 *secid)
{
	
}

static int s2os_task_setnice(struct task_struct *p, int nice)
{
	return 0;
}

static int s2os_task_setioprio(struct task_struct *p, int ioprio)
{
	return 0;
}

static int s2os_task_getioprio(struct task_struct *p)
{
	return 0;
}

static int s2os_task_setrlimit(struct task_struct *p, unsigned int resource,
		struct rlimit *new_rlim)
{
	return 0;
}

static int s2os_task_setscheduler(struct task_struct *p)
{
	return 0;
}

static int s2os_task_getscheduler(struct task_struct *p)
{
	return 0;
}

static int s2os_task_movememory(struct task_struct *p)
{
	return 0;
}

static int s2os_task_kill(struct task_struct *p, struct siginfo *info,
				int sig, u32 secid)
{
	return 0;
}

static int s2os_task_wait(struct task_struct *p)
{
	return 0;
}

static void s2os_task_to_inode(struct task_struct *p,
				  struct inode *inode)
{

}


/* socket security operations */

static int s2os_socket_create(int family, int type,
				 int protocol, int kern)
{
	return 0;
}

static int s2os_socket_post_create(struct socket *sock, int family,
				      int type, int protocol, int kern)
{
	return 0;
}

static int s2os_socket_bind(struct socket *sock, struct sockaddr *address, int addrlen)
{
   /* 
	printk("[s2os_socket_bind]pid:%x, sin_port:%x, sin_addr:%x\n", current->pid, ((struct sockaddr_in *)address)->sin_port, ((struct sockaddr_in *)address)->sin_addr.s_addr);
    */
    return 0;
}

static int s2os_socket_connect(struct socket *sock, struct sockaddr *address, int addrlen)
{
	    
    //printk("[s2os_socket_connect]pid:%x, destip:%x, srcip:%x, sin_port:%x, sin_addr:%x\n", current->pid, sock->sk->__sk_common.skc_daddr, sock->sk->__sk_common.skc_rcv_saddr, ((struct sockaddr_in *)address)->sin_port, ((struct sockaddr_in *)address)->sin_addr.s_addr);
    
    return 0;
}

static int s2os_socket_listen(struct socket *sock, int backlog)
{
	return 0;
}

static int s2os_socket_accept(struct socket *sock, struct socket *newsock)
{
	return 0;
}

static int s2os_socket_sendmsg(struct socket *sock, struct msghdr *msg,
				  int size)
{
//     int ret = -20;
//     //struct iphdr *ip_header = ip_header = ip_hdr(skb);
//     //haojin: create a event to lookup sysflow table
//     struct sysflow_system_event *event = NULL;
//     struct sysflow_action *action = NULL;
    
// 	//do_gettimeofday(&start_time);
    
//     event  = (struct sysflow_system_event *)kmalloc(sizeof(struct sysflow_system_event), GFP_ATOMIC);
//     if (event != NULL) {
//         event->len = sizeof(struct sysflow_system_event); 
//         event->hdr = (struct sysflow_system_event_hdr *)kmalloc(sizeof(struct sysflow_system_event_hdr), GFP_ATOMIC);
//         if (event->hdr != NULL) {
//             event->hdr->src_type = SYSFLOW_SRC_PROCESS;
//             event->hdr->dst_type = SYSFLOW_DST_FILE;
//             event->hdr->opcode = SYSFLOW_FILE_APPEND; 
//             event->hdr->pid = current->pid;
//         }
//     }

//     // allocate action
//     action = (struct sysflow_action*)kmalloc(sizeof(struct sysflow_action), GFP_ATOMIC);
    
//     if (action != NULL) {
//         //call sysflow interface
//         ret = s2os_invoke_sysflow_func((void*)(event), (void*)action);
//         switch (ret) {
//             /*
//             case SYSFLOW_ACTION_ENCODE: 
//             {
//                 ip_header->tos = 0xe0;
//                 //printk("[s2os_socket_setsndpkt]pid:%x [SYSFLOW_ACTION_ENCODE]set tos to 0xe0\n", current->pid);
//                 goto ALLOW;
//                 break;
//             }
//             */    
//             default:
//             {
//                 goto ALLOW;
//             }
//         }
//     }

// ALLOW:
//     sweep_event(event);
//     sweep_action(action);

// #ifdef IF_DEBUG_SAMPLE
//     printk("[s2os_socket_sendmsg]pid:%x\n", current->pid);
// #endif

	return 0;
}

static int s2os_socket_recvmsg(struct socket *sock, struct msghdr *msg,
				  int size, int flags)
{
// 	int ret = -20;
//     //struct iphdr *ip_header = ip_header = ip_hdr(skb);
//     //haojin: create a event to lookup sysflow table
//     struct sysflow_system_event *event = NULL;
//     struct sysflow_action *action = NULL;
    
// #ifdef IF_DEBUG_SAMPLE
//     printk("[S2OS] Entering s2os_socket_recvmsg\n");
// #endif
// 	//do_gettimeofday(&start_time);
    
//     event  = (struct sysflow_system_event *)kmalloc(sizeof(struct sysflow_system_event), GFP_ATOMIC);
//     if (event != NULL) {
//         event->len = sizeof(struct sysflow_system_event); 
//         event->hdr = (struct sysflow_system_event_hdr *)kmalloc(sizeof(struct sysflow_system_event_hdr), GFP_ATOMIC);
//         if (event->hdr != NULL) {
//             event->hdr->src_type = SYSFLOW_SRC_PROCESS;
//             event->hdr->dst_type = SYSFLOW_DST_FILE;
//             event->hdr->opcode = SYSFLOW_FILE_APPEND; 
//             event->hdr->pid = current->pid;
//         }
//     }
//     // allocate action
//     action = (struct sysflow_action*)kmalloc(sizeof(struct sysflow_action), GFP_ATOMIC);
    
//     if (action != NULL) {
//         //call sysflow interface
//         ret = s2os_invoke_sysflow_func((void*)(event), (void*)action);
//         switch (ret) {
//             /*
//             case SYSFLOW_ACTION_ENCODE: 
//             {
//                 ip_header->tos = 0xe0;
//                 //printk("[s2os_socket_setsndpkt]pid:%x [SYSFLOW_ACTION_ENCODE]set tos to 0xe0\n", current->pid);
//                 goto ALLOW;
//                 break;
//             }
//             */    
//             default:
//             {
//                 goto ALLOW;
//             }
//         }
//     }

// ALLOW:
//     sweep_event(event);
//     sweep_action(action);
// #ifdef IF_DEBUG_SAMPLE
//     printk("[s2os_socket_recvmsg]pid:%x\n", current->pid);
// #endif
 
    return 0;
}

static int s2os_socket_getsockname(struct socket *sock)
{
	return 0;
}

static int s2os_socket_getpeername(struct socket *sock)
{
	return 0;
}

static int s2os_socket_setsockopt(struct socket *sock, int level, int optname)
{
	return 0;
}

static int s2os_socket_getsockopt(struct socket *sock, int level,
				     int optname)
{
	return 0;
}

static int s2os_socket_shutdown(struct socket *sock, int how)
{
	return 0;
}

static int s2os_socket_unix_stream_connect(struct sock *sock,
					      struct sock *other,
					      struct sock *newsk)
{
	return 0;
}

static int s2os_sb_show_options(struct seq_file *m, struct super_block *sb)
{
	return 0;
}

static int s2os_set_mnt_opts(struct super_block *sb,
				struct security_mnt_opts *opts)
{
	return 0;
}

static int s2os_socket_unix_may_send(struct socket *sock,
					struct socket *other)
{
	return 0;
}
/*
static int s2os_sock_rcv_skb_compat(struct sock *sk, struct sk_buff *skb,
				       u16 family)
{
	return 0;
}
*/
/*
static int s2os_socket_sock_rcv_skb(struct sock *sk, struct sk_buff *skb)
{
	return 0;
}
*/
static int s2os_socket_getpeersec_stream(struct socket *sock, char __user *optval,
					    int __user *optlen, unsigned len)
{
	return 0;
}

static int s2os_socket_getpeersec_dgram(struct socket *sock, struct sk_buff *skb, u32 *secid)
{
	return 0;
}

static int s2os_sk_alloc_security(struct sock *sk, int family, gfp_t priority)
{
	return 0;
}

static void s2os_sk_free_security(struct sock *sk)
{
	
}

static void s2os_sk_clone_security(const struct sock *sk, struct sock *newsk)
{
	
}

static void s2os_sk_getsecid(struct sock *sk, u32 *secid)
{
	
}

static void s2os_sock_graft(struct sock *sk, struct socket *parent)
{
	
}

static int s2os_inet_conn_request(struct sock *sk, struct sk_buff *skb,
				     struct request_sock *req)
{
	return 0;
}

static void s2os_inet_csk_clone(struct sock *newsk,
				   const struct request_sock *req)
{
	
}

static void s2os_inet_conn_established(struct sock *sk, struct sk_buff *skb)
{
	
}

static int s2os_secmark_relabel_packet(u32 sid)
{
	return 0;
}

static void s2os_secmark_refcount_inc(void)
{

}

static void s2os_secmark_refcount_dec(void)
{
	
}

static void s2os_req_classify_flow(const struct request_sock *req,
				      struct flowi *fl)
{
	
}

static int s2os_tun_dev_create(void)
{
	return 0;
}

static void s2os_tun_dev_post_create(struct sock *sk)
{
	
}

static int s2os_tun_dev_attach(struct sock *sk)
{
	return 0;
}
/*
static int s2os_nlmsg_perm(struct sock *sk, struct sk_buff *skb)
{
	return 0;
}
*/

static int s2os_netlink_send(struct sock *sk, struct sk_buff *skb)
{

	return 0;
}

static int s2os_netlink_recv(struct sk_buff *skb, int capability)
{
	return 0;
}
/*
static int ipc_alloc_security(struct task_struct *task,
			      struct kern_ipc_perm *perm,
			      u16 sclass)
{
	return 0;
}

static void ipc_free_security(struct kern_ipc_perm *perm)
{
	
}
*/

static int s2os_msg_msg_alloc_security(struct msg_msg *msg)
{
	return 0;
}

static void s2os_msg_msg_free_security(struct msg_msg *msg)
{
	
}

static int s2os_msg_queue_alloc_security(struct msg_queue *msq)
{
	return 0;
}

static void s2os_msg_queue_free_security(struct msg_queue *msq)
{
	
}

static int s2os_msg_queue_associate(struct msg_queue *msq, int msqflg)
{
	return 0;
}

static int s2os_msg_queue_msgctl(struct msg_queue *msq, int cmd)
{
	return 0;
}

static int s2os_msg_queue_msgsnd(struct msg_queue *msq, struct msg_msg *msg, int msqflg)
{
	return 0;
}

static int s2os_msg_queue_msgrcv(struct msg_queue *msq, struct msg_msg *msg,
				    struct task_struct *target,
				    long type, int mode)
{
	return 0;
}


/* Shared Memory security operations */

static int s2os_shm_alloc_security(struct shmid_kernel *shp)
{
	return 0;
}

static void s2os_shm_free_security(struct shmid_kernel *shp)
{
	
}

static int s2os_shm_associate(struct shmid_kernel *shp, int shmflg)
{
	return 0;
}

static int s2os_shm_shmctl(struct shmid_kernel *shp, int cmd)
{
	return 0;
}

static int s2os_shm_shmat(struct shmid_kernel *shp,
			     char __user *shmaddr, int shmflg)
{
	return 0;
}


/* Semaphore security operations */

static int s2os_sem_alloc_security(struct sem_array *sma)
{
return 0;
}

static void s2os_sem_free_security(struct sem_array *sma)
{

}

static int s2os_sem_associate(struct sem_array *sma, int semflg)
{
	return 0;
}

static int s2os_sem_semctl(struct sem_array *sma, int cmd)
{
	return 0;
}

static int s2os_sem_semop(struct sem_array *sma,
			     struct sembuf *sops, unsigned nsops, int alter)
{
	return 0;
}

static int s2os_ipc_permission(struct kern_ipc_perm *ipcp, short flag)
{
	return 0;
}

static void s2os_ipc_getsecid(struct kern_ipc_perm *ipcp, u32 *secid)
{

}

static void s2os_d_instantiate(struct dentry *dentry, struct inode *inode)
{
	
}

static int s2os_getprocattr(struct task_struct *p,
			       char *name, char **value)
{
	return 0;
}

static int s2os_setprocattr(struct task_struct *p,
			       char *name, void *value, size_t size)
{
	return 0;
}

static int s2os_secid_to_secctx(u32 secid, char **secdata, u32 *seclen)
{
	return 0;
}

static int s2os_secctx_to_secid(const char *secdata, u32 seclen, u32 *secid)
{
	return 0;
}

static void s2os_release_secctx(char *secdata, u32 seclen)
{
	
}

static int s2os_inode_notifysecctx(struct inode *inode, void *ctx, u32 ctxlen)
{
	return 0;
}

static int s2os_inode_setsecctx(struct dentry *dentry, void *ctx, u32 ctxlen)
{
	return 0;
}

static int s2os_inode_getsecctx(struct inode *inode, void **ctx, u32 *ctxlen)
{
	return 0;
}

static int s2os_innet_conn_request(struct sock *sk, struct sk_buff *skb, struct request_sock *req) 
{
    /*
    struct ethhdr *eth_header = NULL;
    struct iphdr *ip_header = NULL;
    
    eth_header = (struct ethhdr *)(skb_mac_header(skb));
    //if (eth_header != NULL && eth_header->h_proto == ETH_P_IP){
        ip_header = (struct iphdr *)(skb_network_header(skb));
        printk("[s2os_innet_conn_request]src IP:'"NIPQUAD_FMT"', dst IP:'"NIPQUAD_FMT"' \n",
                     NIPQUAD(ip_header->saddr), NIPQUAD(ip_header->daddr));    
        ip_header->tos = 0xe0;
    
        printk("[s2os_innet_conn_request]set tos to 0xe0\n");
    //}
    */
    return 0;
}

static int s2os_innet_conn_established(struct sock *sk, struct sk_buff *skb)
{
    /*    
    struct ethhdr *eth_header = NULL;
    struct iphdr *ip_header = NULL;

    eth_header = (struct ethhdr *)(skb_mac_header(skb));
    if (eth_header != NULL && htons(eth_header->h_proto) == ETH_P_IP){
        printk("[s2os_innet_conn_established]protocol:%x\n", eth_header->h_proto); 
        ip_header = (struct iphdr *)(skb_network_header(skb));
        printk("[s2os_innet_conn_established]src IP:'"NIPQUAD_FMT"', dst IP:'"NIPQUAD_FMT"' \n",
                     NIPQUAD(ip_header->saddr), NIPQUAD(ip_header->daddr));    
        ip_header->tos = 0xd0;
        printk("[s2os_innet_conn_established]set tos to 0xd0\n");
    }
    */
    return 0;
}


static void s2os_socket_setsndpkt(struct sock *sk, struct sk_buff *skb)
{
    /*
    int ret = -20;
    struct iphdr *ip_header = ip_header = ip_hdr(skb);
    //haojin: create a event to lookup sysflow table
    struct sysflow_system_event *event = NULL;
    struct sysflow_action *action = NULL;
    
	//do_gettimeofday(&start_time);
    
    event  = (struct sysflow_system_event *)kmalloc(sizeof(struct sysflow_system_event), GFP_ATOMIC);
    if (event != NULL) {
        event->len = sizeof(struct sysflow_system_event); 
        event->hdr = (struct sysflow_system_event_hdr *)kmalloc(sizeof(struct sysflow_system_event_hdr), GFP_ATOMIC);
        if (event->hdr != NULL) {
            event->hdr->src_type = SYSFLOW_SRC_PROCESS;
            event->hdr->dst_type = SYSFLOW_DST_FILE;
            event->hdr->opcode = SYSFLOW_FILE_APPEND; 
            event->hdr->pid = current->pid;
        }
    }
    // allocate action
    action = (struct sysflow_action*)kmalloc(sizeof(struct sysflow_action), GFP_ATOMIC);
    
    if (action != NULL) {
        //call sysflow interface
        ret = s2os_invoke_sysflow_func((void*)(event), (void*)action);
        switch (ret) {
            case SYSFLOW_ACTION_ENCODE: 
            {
                ip_header->tos = 0xe0;
                //printk("[s2os_socket_setsndpkt]pid:%x [SYSFLOW_ACTION_ENCODE]set tos to 0xe0\n", current->pid);
                goto ALLOW;
                break;
            }
                
            default:
            {
                goto ALLOW;
            }
        }
    }

ALLOW:
    sweep_event(event);
    sweep_action(action);
    */
    /* 
	do_gettimeofday(&stop_time);
    t = stop_time.tv_sec - start_time.tv_sec;
	t *= 1000000;
	if (stop_time.tv_usec < start_time.tv_usec)
		t -= start_time.tv_usec - stop_time.tv_usec;
	else
		t += stop_time.tv_usec - start_time.tv_usec;
    printk("[s2os_socket_setsndpkt]time: %u\n", t);
    */
    /* 
    int x = 10;
	int y;

	if (ht_contains(&table, &x)) {
		y = *(int *)ht_lookup(&table, &x);
		//Or use convenience macros
		//y = HT_LOOKUP_AS(int, &table, &x);
		//printk(KERN_INFO "[s2os_socket_setsndpkt] %d's value is: %d\n", x, y);
	}
    */
    //ip_header->tos = 0xe0;
    //printk("[s2os_socket_setsndpkt]pid:%x set tos to 0xe0\n", current->pid);
}

static int s2os_socket_getrcvpkt(struct sk_buff *skb)
{
    /*
    int ret;
    struct iphdr *ip_header = ip_header = ip_hdr(skb);
    //haojin: create a event to lookup sysflow table
    struct sysflow_system_event *event = NULL;
    struct sysflow_action *action = NULL;
    event  = (struct sysflow_system_event*)kmalloc(sizeof(struct sysflow_system_event), GFP_ATOMIC);
    if (event != NULL) {
        event->len = sizeof(struct sysflow_system_event); 
        event->hdr = (struct sysflow_system_event_hdr *)kmalloc(sizeof(struct sysflow_system_event_hdr), GFP_ATOMIC);
        if (event->hdr != NULL) {
            event->hdr->src_type = SYSFLOW_SRC_PROCESS;
            event->hdr->dst_type = SYSFLOW_DST_FILE;
            event->hdr->opcode = SYSFLOW_FILE_APPEND; 
            event->hdr->pid = current->pid;
        }
    }
        // allocate action
    action = (struct sysflow_action*)kmalloc(sizeof(struct sysflow_action), GFP_ATOMIC);
    
    if (action != NULL) {
        //call sysflow interface
        ret = s2os_invoke_sysflow_func((void*)(event), (void*)action);
        switch (ret) {
        case SYSFLOW_ACTION_DECODE: 
        {
            printk("[s2os_socket_getrcvpkt]pid:%x get tos: %x\n", current->pid, ip_header->tos);
            goto ALLOW;
            break;
        }
                
        default:
            goto ALLOW;
        }
    }

ALLOW:
    sweep_event(event);
    sweep_action(action);
    */
    /*
    do_gettimeofday(&stop_time);
    t = stop_time.tv_sec - start_time.tv_sec;
	t *= 1000000;
	if (stop_time.tv_usec < start_time.tv_usec)
		t -= start_time.tv_usec - stop_time.tv_usec;
	else
		t += stop_time.tv_usec - start_time.tv_usec;
    printk("[s2os_socket_setsndpkt]time: %u\n", t);
    */
   // printk("[s2os_socket_getrcvpkt]pid:%x get tos: %x\n", current->pid, ip_header->tos);
    return 0;

}


static int s2os_socket_sock_rcv_skb(struct sock *sk, struct sk_buff *skb)
{
    /* 
    struct ethhdr *eth_header = NULL;
    struct iphdr *ip_header = NULL;
    if (skb_mac_header_was_set(skb)){
        eth_header = (struct ethhdr *)(skb_mac_header(skb));
    }
    if (eth_header != NULL && htons(eth_header->h_proto) == ETH_P_IP){
        ip_header = (struct iphdr *)(skb_network_header(skb));
        printk("[s2os_socket_sock_rcv_skb]src IP:'"NIPQUAD_FMT"', dst IP:'"NIPQUAD_FMT"' \n",
                     NIPQUAD(ip_header->saddr), NIPQUAD(ip_header->daddr));    
        ip_header->tos = 0xc0;
        printk("[s2os_socket_sock_rcv_skb]set tos to 0xc0\n");
    }
    */
    return 0;

}


static struct security_operations s2os_ops = {
#if 0
	.inode_permission =		s2os_inode_permission,
	.inode_init_security =		s2os_inode_init_security,
#endif
	.name 						=		"sample",
	.file_permission 			=		s2os_file_permission,
	
	.ptrace_access_check 		=		s2os_ptrace_access_check,
	.ptrace_traceme 			=		s2os_ptrace_traceme,
	.capget 					=		s2os_capget,
	.capset 					=		s2os_capset,
	.capable 					=		s2os_capable,
	.quotactl 					=		s2os_quotactl,
	.quota_on 					=		s2os_quota_on,
	.syslog 					=		s2os_syslog,
	.vm_enough_memory 			=		s2os_vm_enough_memory,

	.netlink_send 				=		s2os_netlink_send,
	.netlink_recv 				=		s2os_netlink_recv,

	.bprm_set_creds 			=		s2os_bprm_set_creds,
	.bprm_committing_creds 		=		s2os_bprm_committing_creds,
	.bprm_committed_creds 		=		s2os_bprm_committed_creds,
	.bprm_secureexec 			=		s2os_bprm_secureexec,

	.sb_alloc_security 			=		s2os_sb_alloc_security,
	.sb_free_security 			=		s2os_sb_free_security,
	.sb_copy_data 				=		s2os_sb_copy_data,
	.sb_remount 				=		s2os_sb_remount,
	.sb_kern_mount 				=		s2os_sb_kern_mount,
	.sb_show_options 			=		s2os_sb_show_options,
	.sb_statfs 					=		s2os_sb_statfs,
	.sb_mount 					=		s2os_mount,
	.sb_umount			 		=		s2os_umount,
	.sb_set_mnt_opts 			=		s2os_set_mnt_opts,
	.sb_clone_mnt_opts 			=		s2os_sb_clone_mnt_opts,
	.sb_parse_opts_str 			= 		s2os_parse_opts_str,

	.inode_alloc_security 		=		s2os_inode_alloc_security,
	.inode_free_security 		=		s2os_inode_free_security,
	.inode_init_security 		=		s2os_inode_init_security,
	.inode_create 				=		s2os_inode_create,
	.inode_link 				=		s2os_inode_link,
	.inode_unlink 				=		s2os_inode_unlink,
	.inode_symlink 				=		s2os_inode_symlink,
	.inode_mkdir 				=		s2os_inode_mkdir,
	.inode_rmdir 				=		s2os_inode_rmdir,
	.inode_mknod 				=		s2os_inode_mknod,
	.inode_rename 				=		s2os_inode_rename,
	.inode_readlink 			=		s2os_inode_readlink,
	.inode_follow_link 			=		s2os_inode_follow_link,
	.inode_permission 			=		s2os_inode_permission,
	.inode_setattr 				=		s2os_inode_setattr,
	.inode_getattr 				=		s2os_inode_getattr,
	.inode_setxattr 			=		s2os_inode_setxattr,
	.inode_post_setxattr 		=		s2os_inode_post_setxattr,
	.inode_getxattr 			=		s2os_inode_getxattr,
	.inode_listxattr 			=		s2os_inode_listxattr,
	.inode_removexattr 			=		s2os_inode_removexattr,
	.inode_getsecurity			=		s2os_inode_getsecurity,
	.inode_setsecurity 			=		s2os_inode_setsecurity,
	.inode_listsecurity 		=		s2os_inode_listsecurity,
	.inode_getsecid 			=		s2os_inode_getsecid,

//	.file_permission	 		=		s2os_file_permission,
	
	.file_alloc_security 		=		s2os_file_alloc_security,
	.file_free_security 		=		s2os_file_free_security,
	.file_ioctl 				=		s2os_file_ioctl,
	.file_mmap 					=		s2os_file_mmap,
	.file_mprotect			 	=		s2os_file_mprotect,
	.file_lock 					=		s2os_file_lock,
	.file_fcntl 				=		s2os_file_fcntl,
	.file_set_fowner 			=		s2os_file_set_fowner,
	.file_send_sigiotask 		=		s2os_file_send_sigiotask,
	.file_receive 				=		s2os_file_receive,

	.dentry_open 				=		s2os_dentry_open,

	.task_create 				=		s2os_task_create,
	.cred_alloc_blank 			=		s2os_cred_alloc_blank,
	.cred_free 					=		s2os_cred_free,
	.cred_prepare 				=		s2os_cred_prepare,
	.cred_transfer 				=		s2os_cred_transfer,
	.kernel_act_as 				=		s2os_kernel_act_as,
	.kernel_create_files_as 	=		s2os_kernel_create_files_as,
	.kernel_module_request 		=		s2os_kernel_module_request,
	.task_setpgid 				=		s2os_task_setpgid,
	.task_getpgid 				=		s2os_task_getpgid,
	.task_getsid 				=		s2os_task_getsid,
	.task_getsecid 				=		s2os_task_getsecid,
	.task_setnice 				=		s2os_task_setnice,
	.task_setioprio 			=		s2os_task_setioprio,
	.task_getioprio 			=		s2os_task_getioprio,
	.task_setrlimit 			=		s2os_task_setrlimit,
	.task_setscheduler 			=		s2os_task_setscheduler,
	.task_getscheduler	 		=		s2os_task_getscheduler,
	.task_movememory 			=		s2os_task_movememory,
	.task_kill 					=		s2os_task_kill,
	.task_wait 					=		s2os_task_wait,
	.task_to_inode 				=		s2os_task_to_inode,

	.ipc_permission 			=		s2os_ipc_permission,
	.ipc_getsecid 				=		s2os_ipc_getsecid,

	.msg_msg_alloc_security 	=		s2os_msg_msg_alloc_security,
	.msg_msg_free_security 		=		s2os_msg_msg_free_security,

	.msg_queue_alloc_security 	=		s2os_msg_queue_alloc_security,
	.msg_queue_free_security 	=		s2os_msg_queue_free_security,
	.msg_queue_associate 		=		s2os_msg_queue_associate,
	.msg_queue_msgctl 			=		s2os_msg_queue_msgctl,
	.msg_queue_msgsnd 			=		s2os_msg_queue_msgsnd,
	.msg_queue_msgrcv 			=		s2os_msg_queue_msgrcv,

	.shm_alloc_security 		=		s2os_shm_alloc_security,
	.shm_free_security 			=		s2os_shm_free_security,
	.shm_associate 				=		s2os_shm_associate,
	.shm_shmctl 				=		s2os_shm_shmctl,
	.shm_shmat 					=		s2os_shm_shmat,

	.sem_alloc_security 		=		s2os_sem_alloc_security,
	.sem_free_security 			=		s2os_sem_free_security,
	.sem_associate 				=		s2os_sem_associate,
	.sem_semctl 				=		s2os_sem_semctl,
	.sem_semop 					=		s2os_sem_semop,

	.d_instantiate 				=		s2os_d_instantiate,

	.getprocattr 				=		s2os_getprocattr,
	.setprocattr 				=		s2os_setprocattr,

	.secid_to_secctx 			=		s2os_secid_to_secctx,
	.secctx_to_secid 			=		s2os_secctx_to_secid,
	.release_secctx 			=		s2os_release_secctx,
	.inode_notifysecctx 		=		s2os_inode_notifysecctx,
	.inode_setsecctx 			=		s2os_inode_setsecctx,
	.inode_getsecctx 			=		s2os_inode_getsecctx,

	.unix_stream_connect 		=		s2os_socket_unix_stream_connect,
	.unix_may_send 				=		s2os_socket_unix_may_send,

	.socket_create 				=		s2os_socket_create,
	.socket_post_create 		=		s2os_socket_post_create,
	.socket_bind 				=		s2os_socket_bind,
	.socket_connect 			=		s2os_socket_connect,
	.socket_listen 				=		s2os_socket_listen,
	.socket_accept 				=		s2os_socket_accept,
	.socket_sendmsg 			=		s2os_socket_sendmsg,
	.socket_recvmsg 			=		s2os_socket_recvmsg,
	.socket_getsockname 		=		s2os_socket_getsockname,
	.socket_getpeername		 	=		s2os_socket_getpeername,
	.socket_getsockopt 			=		s2os_socket_getsockopt,
	.socket_setsockopt 			=		s2os_socket_setsockopt,
	.socket_shutdown 			=		s2os_socket_shutdown,
	//.socket_sock_rcv_skb 		=		s2os_socket_sock_rcv_skb,
	.socket_getpeersec_stream 	= 		s2os_socket_getpeersec_stream,
	.socket_getpeersec_dgram  	= 		s2os_socket_getpeersec_dgram,
	.sk_alloc_security 			= 		s2os_sk_alloc_security,
	.sk_free_security 			= 		s2os_sk_free_security,
	.sk_clone_security 			= 		s2os_sk_clone_security,
	.sk_getsecid 				= 		s2os_sk_getsecid,
	.sock_graft 				= 		s2os_sock_graft,
	.inet_conn_request 			= 		s2os_inet_conn_request,
	.inet_csk_clone 			= 		s2os_inet_csk_clone,
	.inet_conn_established		=	  	s2os_inet_conn_established,
	.secmark_relabel_packet 	= 		s2os_secmark_relabel_packet,
	.secmark_refcount_inc 		= 		s2os_secmark_refcount_inc,
	.secmark_refcount_dec 		= 		s2os_secmark_refcount_dec,
	.req_classify_flow 			= 		s2os_req_classify_flow,
	.tun_dev_create 			= 		s2os_tun_dev_create,
	.tun_dev_post_create 		= 		s2os_tun_dev_post_create,
	.tun_dev_attach 			= 		s2os_tun_dev_attach,
    .inet_conn_request          =       s2os_innet_conn_request,
    .inet_conn_established      =       s2os_innet_conn_established,
    //haojin
    .socket_setsndpkt           =       s2os_socket_setsndpkt,
    .socket_getrcvpkt           =       s2os_socket_getrcvpkt,
    .socket_sock_rcv_skb        =       s2os_socket_sock_rcv_skb,
};

static __init int s2os_mod_init(void)
{
	if (!security_module_enable(&s2os_ops) || register_security (&s2os_ops)) {
		printk(KERN_ALERT "s2os: Unable to register with kernel.\n");
		return 0;
	}
    s2os_init();

	printk(KERN_ALERT "s2os:  Initialized.\n");

	return 0;
}


security_initcall(s2os_mod_init);


