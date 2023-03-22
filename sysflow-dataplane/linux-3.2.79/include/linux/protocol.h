#ifndef PROTOCOL_H
#define PROTOCOL_H 1

#define MAC_LEN 6

#include <linux/kernel.h>
#include <linux/types.h>

// [H10] kevin, variable length src/dst name required
#define SFPFM_MAX_NAME  256

// [H28] kevin, define an action report message
#define SFPACT_MAX_DATA  256

/*
struct file_id {
	uint32_t uuid;
	uint32_t inode_num;
};
*/


enum sfp_type {
	SFP_HELLO = 0,			
	SFP_INFO_REQUEST = 1,
	SFP_INFO_REPLY = 2,
	SFP_FLOW_MOD = 3,
	SFP_FLOW_STATE_REQUEST = 4,
	SFP_FLOW_STATE_REPORT = 5,
	SFP_ECHO_REQUEST = 6,           // [H8] kevin, add echo message
	SFP_ECHO_REPLY = 7,              // [H8] kevin, add echo message
    SFP_ACTION_REPORT = 8           // [H28] kevin, define a action report message
};

/* Header of all sysflow message. */
struct sfp_header {
	uint32_t length; /* Length including this sfp_header. */
	uint32_t type; /* Type of sysflow message */
	uint32_t xid; /* Transaction id associated with this message */
};

/*Sysflow hello message: host <-> controller*/
struct sfp_hello{
	struct sfp_header header;
};

#define SFP_HELLO_MSG_SIZE sizeof(struct sfp_hello)


/*Sysflow Host Information Request message: controller -> host*/
struct sfp_info_request{
	struct sfp_header header;
};

/*The identifier for host*/
struct host_id{
	uint8_t mac[MAC_LEN];	/*we use hardware address to present each host*/
};

/*The enum for os type of host*/

enum host_os_type{
	OS_WINDOWS_XP = 0,
	OS_WINDOWS_7 = 1,
	OS_WINDOWS_8 = 2,
	OS_WINDOWS_10 = 3,
	OS_LINUX = 4
};


struct host_info{

    // [H5] kevin, controller expects host's mac address
	//struct host_id hid;	   /*ignore host info here*/
	struct host_id hid;	   
	uint32_t os_type;		/*Operating System type*/

	uint32_t core_num;	/*The number of CPU cores*/
};

/*Sysflow Host Inforamtion Reply message: host -> controller*/
struct sfp_info_reply{
	struct sfp_header header;
	struct host_info hinfo;
};

#define SFP_INFO_REPLY_MSG_SIZE sizeof(struct sfp_info_reply)

enum sfp_flow_mod_type{
	SFPFM_ADD = 0,
	SFPFM_REMOVE = 1,
	SFPFM_UPDATE = 2
};

// [H6] kevin, correct mismatch with controller's definitions
/*
enum sfp_action_type {
    SYSFLOW_ACTION_UNKOWN = 0, 
    SYSFLOW_ACTION_ALLOW = 1, 		
    SYSFLOW_ACTION_DENY = 2, 		
    SYSFLOW_ACTION_REDIRECT = 3, 		
    SYSFLOW_ACTION_QRAUNTINE = 4, 		
    SYSFLOW_ACTION_TAG = 5, 		
    SYSFLOW_ACTTION_ISOLATION = 6, 
    SYSFLOW_ACTION_MIGRATION = 7, 
    SYSFLOW_ACTION_LOG = 8, 
    SYSFLOW_ACTION_ALERT = 9, 
    SYSFLOW_ACTION_MESSAGE = 10, 
    SYSFLOW_ACTION_NEXTMODULE = 11
};
*/
/*
enum sfp_action_type {
    SYSFLOW_ACTION_UNKOWN       = 0, 
    SYSFLOW_ACTION_ALLOW        = 1, 		
    SYSFLOW_ACTION_DENY         = 2, 		
    SYSFLOW_ACTION_REDIRECT     = 3, 		
    SYSFLOW_ACTION_QRAUNTINE    = 4, 		
    SYSFLOW_ACTTION_ISOLATION   = 5, 
    SYSFLOW_ACTION_MIGRATION    = 6, 
    SYSFLOW_ACTION_ENCODE       = 7, 		
    SYSFLOW_ACTION_DECODE       = 8, 		
    SYSFLOW_ACTION_LOG          = 9, 
    SYSFLOW_ACTION_REPORT       = 10, 
    SYSFLOW_ACTION_MESSAGE      = 11, 
    SYSFLOW_ACTION_NEXTMODULE   = 12
};
*/
// [H31] kevin, action reason definitions
// @note: bitwise operations  
//        order of data should follow the order of the following definitions
enum sfp_action_report_reason {
    // 1. this bit makes an action report message delivered to controller 
    SYSFLOW_ACTION_REPORT_REASON_REPORT_TO_CONTROLLER   = (1 << 1),
    // 2. this bit makes an action report mesage notified to user
    SYSFLOW_ACTION_REPORT_REASON_ALERT_TO_USER          = (1 << 2),
    // 3. this bit is used to inform that a flow is hit.
    // data should contain byte hits (4B), event hits (4B) in order.
    // following data should contain the current action_len(4B) and action_data(variable length in bytes) in order.
    SYSFLOW_ACTION_REPORT_REASON_MATCH_HIT              = (1 << 3),
    // 4. this bit is used to inform that the current action has been just conducted successfully 
    // data should contain the current action_len (4B) and action_data in order
    SYSFLOW_ACTION_REPORT_REASON_ACTION_SUCCESS         = (1 << 4),
    // 5. this bit is used to inform that the current action has just failed to run for specific reasons.
    // data should contain the current action_len (4B) and action _data in order 
    // the following data should contain the reasons
    // TODO: the reasons for now we could use SYSFLOW_ACTION_REPORT_REASON_STRING_MESSAGE and we could redefine a new data structure for this later.         
    SYSFLOW_ACTION_REPORT_REASON_ACTION_FAILURE         = (1 << 5),
    // 6. this bit is used to contain a string of any message.
    SYSFLOW_ACTION_REPORT_REASON_STRING_MESSAGE         = (1 << 6)
};




struct sfp_action{
    uint32_t type;
    uint32_t len;		//the total length of sysflow action
    // kevin, FIXME: data should be variale length
    uint8_t data;	    //The length is inferred from the length field.
};

// [H6] kevin, correct mismatch with controller's definitions
/*
enum sfp_match_type{
	SFP_MATCH_PID = 0,
	SFP_MATCH_NAME = 1,
	SFP_MATCH_REGEX = 20
};
*/
enum sfp_match_type{
	SFP_MATCH_ID = 0,           // [H27]
	SFP_MATCH_NAME = 1,
	SFP_MATCH_REGEX = 2,
    SFP_MATCH_SOCKET = 3
};

struct sfp_match{
	uint32_t src_type;
	uint32_t src_len;
	//union src {
    uint32_t pid;

    // [H10] kevin, variable length src/dst name required
    //char src_name[20];	         //field for src name and regex, max len is 20, the actual len is inferred from src_len
    char src_name[SFPFM_MAX_NAME];	         //field for src name and regex, max len is 20, the actual len is inferred from src_len
	//}src;

	uint32_t dst_type;
	uint32_t dst_len;
	//union dst {
    struct file_id fid;
    // [H10] kevin, variable length src/dst name required
    //char dst_name[20];	        //field for dst name and regex, max len is 20, the actual len is inferred from src_len
    char dst_name[SFPFM_MAX_NAME];	        //field for dst name and regex, max len is 20, the actual len is inferred from src_len
	//}dst;

	uint32_t mask;			   //mask for 3-tuple(src, dst, opcode)
	uint32_t opcode;		   //defined in event.h
};

#define SFP_MATCH_SIZE sizeof(struct sfp_match)

//Sysflow Flow Modification message: controller -> host
struct sfp_flow_mod{
	struct sfp_header header;

    // [H6] kevin, correct mismatch with controller's definitions
	uint32_t type;		//type of flow mod

	struct sfp_match match;

    // [H6] kevin, correct mismatch with controller's definitions
	//uint32_t type;		//type of flow mod

	uint32_t priority;  //Priority level of flow entry.

	uint32_t actions_len;  //total Size of action array in bytes.
	struct sfp_action actions[];    //The action length is inferred from length field
};

//Sysflow Flow State Request message: controller -> host
struct sfp_flow_stats_request{
	struct sfp_header header;
	
	struct sfp_match match;
};

struct sfp_flow_stats_reply{
    struct sfp_header header;
    
    struct sfp_match match;

    uint32_t event_hits;
    uint32_t byte_hits;
};

//Sysflow Flow State Request message: host -> controller
struct sfp_flow_report{
	struct sfp_header header;

	struct sfp_match match;
	uint32_t event_count;	 //Number of events in flow.
    uint32_t byte_count; 	//Number of bytes in flow.
    
    //TODO: add extensible metadata here

	//struct sfp_action_header actions[0]; //The action length is inferred from length field

};
// [H28] kevin, define an action report message
struct sfp_action_report{
    struct sfp_header header;
    
    struct sfp_match match;

    uint32_t action_type;
    uint32_t reason;
    uint32_t data_len;
    uint8_t data[SFPACT_MAX_DATA];
};


// [H8] new struct for utok_info
#define UTOK_MAX_ACTION_BUFFER  256
struct utok_flow_mod {

    uint32_t type;
    struct sfp_match match;
    uint32_t priority;
    uint32_t action_num;
    uint8_t action_buffer[UTOK_MAX_ACTION_BUFFER];
};
struct utok_flow_stats_request {
    struct sfp_match match;
};
struct ktou_flow_stats_reply {
    struct sfp_match match;
    uint32_t event_hits;
    uint32_t byte_hits;
};
// [H19] kevin, define an action report message
struct ktou_action_report {
    
    struct sfp_match match;

    uint32_t action_type;
    uint32_t reason;
    uint32_t data_len;
    uint8_t data[SFPACT_MAX_DATA];
};
union utok_protocol{
    struct utok_flow_mod flowmod;
    struct utok_flow_stats_request statsreq;
    struct ktou_flow_stats_reply   statsrep;
    // [H19] kevin, define an action report message
    struct ktou_action_report actreport;
};
struct utok_info{
    struct sfp_header header;
    union utok_protocol protocol;
};


// [H8] kevin, add echo message
struct sfp_echo{
	struct sfp_header header;
};

#define SFP_ECHO_MSG_SIZE sizeof(struct sfp_echo)

#endif /*protocol.h*/
