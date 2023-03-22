/**
 * History
 * 
 * [H1] kevin, action_len is missing type and len when storing to pass_info->action_buffer for netlink
 * [H2] kevin, prevent modifying the interator, i
 * [H3] kevin, host info definitions
 * [H4] kevin, add a function to retrieve host MAC address for host info
 * [H5] kevin, controller expects host' mac from SFP_INFO_REPLY
 * [H6] kevin, after controller sends a flowmod, client disconnects right away and then controller sends a empty message  with 0 length payload multiple times.
 * [H7] kevin, handle disconnection from controller correctly
 * [H8] kevin, echo message
 * [H9] kevin, FIXME: src/dst type should be handled acording to definitions. priority is not passed to flowtable.
 * [H10] kevin, variable length src/dst name required
 * [H11] kevin, msg/flowmod type and priority are missing in utok_info struct
 * [H12] kevin, action_len should be the total number of actions
 * [H13] kevin, wrong action code length is used
 * [H14] kevin, action_len should have only the length of action code not type and len
 * [H15] kevin, should use a reasonable defined constant value
 * [H16] kevin, stats reply message raises an exception in the controller
 * [H17] kevin, fix stats reply in terms of variable length src/dst name
 * [H18] kevin, use constant number of action buffer size
 * [H19] kevin, kernel doesn't have access to src/dst name which includes network flow info
 * [H20] new struct for utok_info
 * [H21] kevin, NOTE: action type and len are not coverted to host order
 * [H22] kevin, FIXME: return message from the kernel should be non-blocking
 * [H23] kevin, use network byte order when sending packets to controller
 * [H24] kevin, FIXME: use a reasonable xid pool
 * [H25] kevin, fix seg fault from action parsing
 * [H26] kevin, use adjusted inode number and PID
 * [H27] kevin, use consistent name with controller
 * [H28] kevin, define a action report message
 * [H29] kevin, create a thread to receive an asynchronous message from kernel
 * [H30] kevin, declare as a global variable for nl_recv_thread to send a packet to controller
 * [H31] kevin, action reason definitions
 * [H32] kevin, fix send buffer length
 * [H33] kevin, FIXED: need to fix bugs in controller when receiving ACTION_REPORT, currently client print user AlerT message and do not send to contoller
 * [H34] kevin, enabled the sending code that disabled for testing ACTION_REPORT
 * [H35] kevin, added same logic of [H9] for stats reply
 * [H36] kevin, FIXME: pid search function doesn't extract the correct file, e.g., search for "client" will return two "dhclient" and "client", which is confusing
 * [H37] kevin, reconnection handling code when controller is not listening
 * [H38] kevin, use xid 0 for hello, use xid pool for client-initiating message
 * 
 **/

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/types.h>  
#include <sys/socket.h>  
#include <netinet/in.h>  
#include <arpa/inet.h>  
#include <string.h>
#include <unistd.h>
#include <math.h>
#include <linux/netlink.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <net/if.h> 
#include <limits.h> // [H38]

// [H29] kevin, create a thread to receive an asynchronous message from kernel
#include <pthread.h>


#include "protocol.h"

// [H3] kevin, host info definitions
#define HOST_OS_TYPE    OS_LINUX
#define HOST_OS_CORE    2


#define NETLINK_USER 31
// [H29] kevin, create a thread to receive an asynchronous message from kernel
#define NETLINK_USER_KTOU 17
#define NETLINK_USER_KTOU_GROUP 1

#define MAX_PAYLOAD 1024 /* maximum payload size*/
struct msghdr msg;
int daemon_status = 0;
#define UTOK_MAX_ACTION_BUFFER    256     // [H18]

// [H30] kevin, declare as a global variable for nl_recv_thread to send a packet to controller
int client_sockfd;  
// [H37] 
int is_connected = 0;
int xidpool = INT_MAX / 2;  // [H38], starts from the middle
 
 // kevin, reconnecton code
#define MAX_RECONNECT_TRIES 200     // 10 mins
#define RECONNECT_INTERVAL  3       // in secs
// [H9][H19]
/*
struct utok_info{
    unsigned int msg_type;              // [H11] kevin, msg/flowmod type and priority are missing in utok_info struct
    unsigned int sub_type;      // [H11] kevin, msg/flowmod type and priority are missing in utok_info struct
    unsigned int pid;
    unsigned int opcode;
    unsigned int mask;
    struct file_id fid;
    unsigned int priority;      // [H11] kevin, msg type and priority are missing in utok_info struct
    unsigned int action_num;
    //unsigned char action_buffer[100];
    unsigned char action_buffer[UTOK_MAX_ACTION_BUFFER];  // [15]
};
*/
// [H20] new struct for utok_info
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
// [H28] kevin, define an action report message
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
    // [H28] kevin, define an action report message
    struct ktou_action_report actreport;
};
struct utok_info{
    struct sfp_header header;
    union utok_protocol protocol;
};

struct parsed_action {
    unsigned int type;
    unsigned int len;
    unsigned char *content;
};

#define BUF_SIZE 1024

// [H38] 
int getNewXid()
{
    xidpool = (xidpool + 1) % INT_MAX;
    if(xidpool == 0)    // 0 is reserved for handshake
        xidpool = (xidpool + 1) % INT_MAX;

    return xidpool;
}

// [H29] kevin, create a thread to receive an asynchronous message from kernel
int g_nl_recv_sock_fd;

int netorder_sfp_action_report(struct sfp_action_report* actreport, char* buf)
{
    int index = 0;
    int src_len, dst_len, data_len;

    //printf("########### header.type: %d \n", actreport->header.type);
    // adjust the length according to varialbe src/dst length and data length
    actreport->header.length = sizeof(struct sfp_action_report)-2*SFPFM_MAX_NAME+actreport->match.src_len+actreport->match.dst_len-SFPACT_MAX_DATA+actreport->data_len;

    //printf("############ heder.length = %d \n", actreport->header.length);

    actreport->header.length = htonl(actreport->header.length);
    actreport->header.type = htonl(actreport->header.type);
    // [H38]
    //actreport->header.xid = htonl(actreport->header.xid);
    actreport->header.xid = htonl(getNewXid());


    actreport->match.src_type = htonl(actreport->match.src_type);
    src_len = actreport->match.src_len;
    //printf("############# src_len: %d \n", src_len);
    actreport->match.src_len = htonl(actreport->match.src_len);
    actreport->match.pid = htonl(actreport->match.pid);
    actreport->match.dst_type = htonl(actreport->match.dst_type);
    dst_len = actreport->match.dst_len;
    //printf("############# dst_len: %d \n", dst_len);
    actreport->match.dst_len = htonl(actreport->match.dst_len);
    actreport->match.fid.uuid = htonl(actreport->match.fid.uuid);
    actreport->match.fid.inode_num = htonl(actreport->match.fid.inode_num);
    actreport->match.mask = htonl(actreport->match.mask);
    actreport->match.opcode = htonl(actreport->match.opcode);

    //printf("############# action_type: %d \n",actreport->action_type );
    actreport->action_type = htonl(actreport->action_type);
    //printf("############# reason: %d \n",actreport->reason );
    actreport->reason = htonl(actreport->reason);
    data_len = actreport->data_len;
    //printf("############# data_len: %d \n", data_len);
    actreport->data_len = htonl(actreport->data_len);
    

    // TODO: currently no byte order conversion here for controller to handle byte order
    if(actreport->reason & SYSFLOW_ACTION_REPORT_REASON_MATCH_HIT)
    {
    }
    else if(actreport->reason & SYSFLOW_ACTION_REPORT_REASON_ACTION_SUCCESS)
    {
    }
    else if(actreport->reason & SYSFLOW_ACTION_REPORT_REASON_ACTION_FAILURE)
    {
    }
    
    // fill out a send buffer according to variable length src/dst name
    memcpy(buf, &actreport->header, sizeof(struct sfp_header) + 12 /*src_type+src_len+pid*/);
    index += sizeof(struct sfp_header) + 12;

    memcpy(buf + index, &actreport->match.src_name, src_len);
    index += src_len;

    memcpy(buf + index, &actreport->match.dst_type,  16/*dst_type+dst_len+fid*/);
    index += 16;

    memcpy(buf + index, &actreport->match.dst_name, dst_len);
    index += dst_len;

    memcpy(buf + index, &actreport->match.mask,  8/*mask+opcode*/);
    
    index += 8;

    memcpy(buf + index, &actreport->action_type,  12/*action_type+reason+data_len*/);
    index += 12;

    memcpy(buf + index, &actreport->data, data_len);
    index += data_len;

    return index;
}

void handle_sfp_action_report(struct sfp_action_report* actreport)
{
    char send_buf[BUF_SIZE];
    int send_buf_len = 0;
    int ret;

    printf("------------- Action Report -------------------\n");
    printf("Header (type: %d, length: %d, xid: %d \n", actreport->header.type, actreport->header.length, actreport->header.xid);
    printf("Action type: %d \n", actreport->action_type);
    printf("Reason: 0x%x \n", actreport->reason);
    printf("-----------------------------------------------\n");
            
    // inform a user of the message
    // TODO: assume an alert to user mesage is a string message for now
    //       we may have to provide users with the same detailed info like alert messages for controller
    if(actreport->reason & SYSFLOW_ACTION_REPORT_REASON_ALERT_TO_USER &&
       actreport->reason & SYSFLOW_ACTION_REPORT_REASON_STRING_MESSAGE)
    {
        printf("============================================\n");
        printf("          Alert Message to Users\n");
        printf("============================================\n");
        printf("Message: %s \n", actreport->data);
    }

    // send a message to controller
    if(actreport->reason & SYSFLOW_ACTION_REPORT_REASON_REPORT_TO_CONTROLLER)
    {
        send_buf_len = netorder_sfp_action_report(actreport, send_buf);
        

        printf("Sending an action report (send_buf_size: %d) to controller...\n", send_buf_len);
        // [H33], [H37]
        //ret = send(client_sockfd, (char *)send_buf, send_buf_len, 0);
        if(is_connected){
            ret = send(client_sockfd, (char *)send_buf, send_buf_len, 0);
            printf("Action report has been sent to controller, send_buf_size: %d \n", ret);
        }
    }
    
}



/*
 * [H29] kevin, create a thread to receive an asynchronous message from kernel
 *
 * @desc:   init nl recv socket for SFP_ACTION_REPORT from kernel
 */
/*
 * [H29] kevin, create a thread to receive an asynchronous message from kernel
 *
 * @desc:  thread for nl recv function for SFP_ACTION_REPORT from kernel 
 */
void* nl_recv_thread(void* args)
{
    struct sockaddr_nl src_addr, dest_addr;
    struct nlmsghdr nlh[NLMSG_SPACE(MAX_PAYLOAD)];
    struct iovec iov;
    struct msghdr msg;
    struct sfp_action_report actreport;

    g_nl_recv_sock_fd=socket(PF_NETLINK, SOCK_RAW, NETLINK_USER_KTOU);

    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = getpid();  /* self pid */
    /* interested in group 1<<0 */

    src_addr.nl_groups = NETLINK_USER_KTOU_GROUP;       // multicast group
    bind(g_nl_recv_sock_fd, (struct sockaddr*)&src_addr,
                   sizeof(src_addr));

    memset(&dest_addr, 0, sizeof(dest_addr));

    memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));

    iov.iov_base = (void *)nlh;
    iov.iov_len = NLMSG_SPACE(MAX_PAYLOAD);
    msg.msg_name = (void *)&dest_addr;
    msg.msg_namelen = sizeof(dest_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    printf("[S2OS] Entering the thread for netlink action report messages...\n");

    while(1)
    {
        recvmsg(g_nl_recv_sock_fd, &msg, 0);

        memcpy(&actreport, NLMSG_DATA(nlh), sizeof(struct sfp_action_report));

        handle_sfp_action_report(&actreport);
    }

}

/*
 * [H4] kevin, add a function to retrieve host MAC address for host info
 *
 * @note: retrieve mac address of only the first found interface
 */
void getHostMacAddress(uint8_t* out_mac)
{
    struct ifreq ifr;
    struct ifconf ifc;
    char buf[1024];
    int success = 0;

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock == -1) { /* handle error*/ };

    ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = buf;
    if (ioctl(sock, SIOCGIFCONF, &ifc) == -1) { /* handle error */ }

    struct ifreq* it = ifc.ifc_req;
    const struct ifreq* const end = it + (ifc.ifc_len / sizeof(struct ifreq));

    for (; it != end; ++it) {
        strcpy(ifr.ifr_name, it->ifr_name);
        if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) {
            if (! (ifr.ifr_flags & IFF_LOOPBACK)) { // don't count loopback
                if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
                    success = 1;
                    break;
                }
            }
        }
        else { /* handle error */ }
    }

    if (success) 
        memcpy(out_mac, ifr.ifr_hwaddr.sa_data, 6);

    printf("Found MAC Address : %02x:%02x:%02x:%02x:%02x:%02x\n", out_mac[0], out_mac[1], out_mac[2], out_mac[3], out_mac[4], out_mac[5]);

}

/*TODO: parse UUID from filename*/

int getInodeFromFileName(char* fname){
	struct stat fileStat;

    if(stat(fname ,&fileStat) < 0){
    	return -1;
    }
    
    return fileStat.st_ino;
}

/*
*return numbers of PID we found
*/

int getPIDFromTaskName(char* tname, int* pids){
   const char* directory = "/proc";
   size_t      taskNameSize = 1024;
   char*       taskName = calloc(1, taskNameSize);
   int pid_index = 0;
   DIR* dir = opendir(directory);
   if (dir)
   {
      struct dirent* de = 0;
      while ((de = readdir(dir)) != 0)
      {
         if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
            continue;
         int pid = -1;
         int res = sscanf(de->d_name, "%d", &pid);
         if (res == 1)
         {
            // we have a valid pid
            // open the cmdline file to determine what's the name of the process running
            char cmdline_file[1024] = {0};
            sprintf(cmdline_file, "%s/%d/cmdline", directory, pid);
            FILE* cmdline = fopen(cmdline_file, "r");
            if (getline(&taskName, &taskNameSize, cmdline) > 0)
            {

                // [H36] kevin, FIXME: pid search function doesn't extract the correct file, e.g., search for "client" will return two "dhclient" and "client", which is confusing
               // is it the process we care about?
               if (strstr(taskName, tname) != 0)
               {
                  fprintf(stdout, "A %s process, with PID %d, has been detected.\n", taskName, pid);
                  pids[pid_index++] = pid;
               }
            }

            fclose(cmdline);
         }
      }
    }
      closedir(dir);

      return pid_index;
}

/*
 * [H-JW-1] Jianwei, add output function to support running as daemon
 * 
 * */
void printLog(char *format, ...){
    va_list valist;
    FILE *fp = fopen("/var/log/sysflow_client.log", "a+");

    va_start(valist, format);
    if(daemon_status == 0)
        vprintf(format, valist);
    else{
        vfprintf(fp, format, valist);
    }
    va_end(valist);

    fclose(fp);
}

void initial_sfp_hello(struct sfp_hello *hello, uint8_t type, uint16_t length, uint32_t xid){

    if(hello != 0) {
	hello->header.type = htonl(type);       // [H23]
	hello->header.length = htonl(length);
	hello->header.xid = htonl(xid);
		
    }
}


void initial_sfp_info_reply(struct sfp_info_reply * sfp_info_reply, struct sfp_header * sfp_header, struct host_info *host_info) {
	/*
	sfp_info_reply->header.type = sfp_header->type;
	sfp_info_reply->header.length= sfp_header->length;
	sfp_info_reply->header.xid = sfp_header->xid;
	//sfp_info_reply->hinfo.hid.mac;
	sfp_info_reply->hinfo.os_type = host_info->os_type;
	sfp_info_reply->hinfo.core_num = host_info->core_num;
	*/

    // [H5] kevin, controller expects host's mac address from SFP_INFO_REPLY
    /*
	sfp_info_reply->header.type = SFP_INFO_REPLY;
	sfp_info_reply->header.length = SFP_INFO_REPLY_MSG_SIZE;
	sfp_info_reply->header.xid = 5;
	sfp_info_reply->hinfo.os_type = 2;
	sfp_info_reply->hinfo.core_num = 2;
    */
    // [H23]
	sfp_info_reply->header.type = htonl(SFP_INFO_REPLY);
	sfp_info_reply->header.length = htonl(SFP_INFO_REPLY_MSG_SIZE);
	sfp_info_reply->header.xid = htonl(5);  // [H24]
    getHostMacAddress(sfp_info_reply->hinfo.hid.mac);
	sfp_info_reply->hinfo.os_type = htonl(HOST_OS_TYPE);
	sfp_info_reply->hinfo.core_num = htonl(HOST_OS_CORE);
}

// [H8] kevin, add echo message
void initial_sfp_echo_request(struct sfp_echo *echo, uint32_t xid)
{
    // [H23]
	echo->header.type = htonl(SFP_ECHO_REQUEST);
	echo->header.length = htonl(SFP_ECHO_MSG_SIZE);
	echo->header.xid = htonl(xid);
}
// [H8] kevin, add echo message
void initial_sfp_echo_reply(struct sfp_echo *echo, uint32_t xid)
{
    // [H23]
	echo->header.type = htonl(SFP_ECHO_REPLY);
	echo->header.length = htonl(SFP_ECHO_MSG_SIZE);
	echo->header.xid = htonl(xid);
}

// [H23]
// [H31]
int netorder_sfp_flow_stats_reply(struct sfp_flow_stats_reply* rep, char* buf)
{
    int index = 0;
    int src_len, dst_len;

    // adjust the length according to varialbe src/dst length
    rep->header.length = sizeof(struct sfp_flow_stats_reply)-2*SFPFM_MAX_NAME+rep->match.src_len+rep->match.dst_len;

    rep->header.length = htonl(rep->header.length);
    rep->header.type = htonl(rep->header.type);
    rep->header.xid = htonl(rep->header.xid);


    rep->match.src_type = htonl(rep->match.src_type);
    src_len = rep->match.src_len;
    rep->match.src_len = htonl(rep->match.src_len);
    rep->match.pid = htonl(rep->match.pid);
    rep->match.dst_type = htonl(rep->match.dst_type);
    dst_len = rep->match.dst_len;
    rep->match.dst_len = htonl(rep->match.dst_len);
    rep->match.fid.uuid = htonl(rep->match.fid.uuid);
    rep->match.fid.inode_num = htonl(rep->match.fid.inode_num);
    rep->match.mask = htonl(rep->match.mask);
    rep->match.opcode = htonl(rep->match.opcode);

    rep->event_hits = htonl(rep->event_hits);
    rep->byte_hits = htonl(rep->byte_hits);
    
    // fill out a send buffer according to variable length src/dst name
    memcpy(buf, &rep->header, sizeof(struct sfp_header) + 12 /*src_type+src_len+pid*/);
    index += sizeof(struct sfp_header) + 12;

    memcpy(buf + index, &rep->match.src_name, src_len);
    index += src_len;

    memcpy(buf + index, &rep->match.dst_type,  16/*dst_type+dst_len+fid*/);
    index += 16;

    memcpy(buf + index, &rep->match.dst_name, dst_len);
    index += dst_len;

    memcpy(buf + index, &rep->match.mask,  16/*mask+opcode+event_hits+byte_hits*/);
    index += 16;

    return index;

}

int client_func(struct sockaddr_in *remote_addr, const char *addr, int port)
{
    int cli_sf = 0;
    memset(remote_addr, 0, sizeof(remote_addr));  
    remote_addr->sin_family = AF_INET;   
    remote_addr->sin_addr.s_addr = inet_addr(addr);  
    remote_addr->sin_port = htons(port);  

    if((cli_sf = socket(PF_INET, SOCK_STREAM, 0)) < 0)  
    {  
        perror("socket");      
    }  
	return cli_sf;		
}

/*
unsigned int byte4toi(unsigned char* p, unsigned int n) {
    unsigned int x = 0;
    unsigned int i = 0;
    while(n > 0){
        n--;
        x = (*(p + n))*pow(256, i++) + x;
    } 
    return x;
}
*/

unsigned int byte4toi(unsigned char* p, unsigned int n) {
    unsigned int x = 0;
    unsigned int i = 0;
    for(; i < n; i++){
        x = (x<<8) + p[i];
    }
    return x;
}


int client_main(char *host, char *port_string)   
{  
	struct sockaddr_nl src_addr, dest_addr;
	struct nlmsghdr *nlh = NULL;
	struct iovec iov;
	int sock_fd;

    // [H30] kevin, declare as a global variable for nl_recv_thread to send a packet to controller
	//int client_sockfd;  
    
    // [H37] 
    int yes = 1;
    int num_conn_tries = 0;

    int len;  
    struct sockaddr_in remote_addr;  
    char send_buf[BUF_SIZE], recv_buf[BUF_SIZE];
    int send_buf_len;     
    struct sfp_hello hello;
    struct sfp_info_reply sfp_info_reply;
    struct sfp_header header;
    
    struct sfp_flow_stats_request stats_request;
    struct sfp_flow_stats_reply stats_reply;

    struct sfp_action_report test_actreport; // kevin, test for sending an action report
    
    struct host_info hinfo;
    struct sfp_flow_mod flow_mode;
    struct sfp_flow_report flow_report;
    enum sfp_type state;
    int port;
    int loop = 1;
    char dump;
    int i, j;
    
    int parsed_pids[100];  
   
    unsigned char* p;
    unsigned int message_len;
    unsigned int message_type;
    unsigned int message_xid;
    unsigned int message_flowmod_type;
    unsigned int message_srctype;
    unsigned int message_srclen;
    unsigned int message_pid;
    // [H10] kevin, variable length src/dst name required
    //unsigned char message_srcname[20];
    unsigned char message_srcname[SFPFM_MAX_NAME];
    unsigned int message_dsttype;
    unsigned int message_dstlen;
    unsigned int message_uuid;
    unsigned int message_inode;
    // [H10] kevin, variable length src/dst name required
    //unsigned char message_dstname[20];
    unsigned char message_dstname[SFPFM_MAX_NAME];
    unsigned int message_mask;
    unsigned int message_opcode;
    //unsigned int message_spf_flowmode_type;   // kevin, unused
    unsigned int message_priority;
    unsigned int message_action_num;
    unsigned char* ptr; 
    struct utok_info *pass_info = NULL;  // kevin, init pointer
    int parsed_inode;
    int parsed_num;
    struct parsed_action *paction = NULL;  // kevin, init pointer
    unsigned int action_len = 0;
    unsigned char *action_ptr;
    struct sfp_match *p_sfp_match;
    struct sfp_header *p_sfp_header;
    struct sfp_flow_stats_request *p_stats_request;
    struct sfp_echo echo_msg;               // [H8] kevin, add echo message

    // [H29] kevin, create a thread to receive an asynchronous message from kernel
    pthread_t nl_thr_id;
    int ret;

    // [H10] kevin, variable length src/dst name required
    memset(message_srcname, 0, SFPFM_MAX_NAME);
    memset(message_dstname, 0, SFPFM_MAX_NAME);

    port = atoi(port_string);

    // [H29] kevin, create a thread to receive an asynchronous message from kernel
    ret = pthread_create(&nl_thr_id, NULL, &nl_recv_thread, NULL);
    // ret = pthread_create(&nl_thr_id, NULL, &nl_recv_thread, (void*)&client_sockfd);
    if(ret == 0){
        printf("netlink recv thread created successfully.\n");
    }
    else{
        printf("netlink recv thread not created.\n");
        return 0; 
    }
    
// [H37]
reconnect:
    client_sockfd = client_func(&remote_addr, host, port);
    if (client_sockfd < 0 ) {
        perror("create socket fail...");  
        return 1;
    }


    // [H37]
   /*    {  
        perror("Error");  
        return 1;  
    }
    */

    while(!is_connected){
        if(connect(client_sockfd,(struct sockaddr *)&remote_addr, sizeof(struct sockaddr)) < 0)  
        {  
            perror("Error");  

            num_conn_tries++;
            if(num_conn_tries <= MAX_RECONNECT_TRIES){
                printf("Reconnecting to Controller... %d tries\n", num_conn_tries);
                sleep(RECONNECT_INTERVAL);
            }
            else{
                printf("Maximum reconnection attemps have reached.\n");
                return 1;  
            }
        }
        else{
            is_connected = 1;
            num_conn_tries = 0;
        }
    }

    printf("Connected to SERVER.\n"); 
    
    //send hello packet to controller
    memset(&hello, 0, sizeof(hello));
    //initial_sfp_hello(&hello, SFP_HELLO, SFP_HELLO_MSG_SIZE, 5);
    initial_sfp_hello(&hello, SFP_HELLO, SFP_HELLO_MSG_SIZE, 0);    // [H38]
    printf("[Send] Hello message (size: %d)\n", sizeof(hello));
    send(client_sockfd, (char *)&hello, sizeof(hello), 0); 

    while(1) {
		memset(recv_buf, 0, sizeof(recv_buf));
		
		if(len = recv(client_sockfd, recv_buf, sizeof(recv_buf), 0)) {
		//check the replied packets: sfp_header.type stands for type
		//TODO parse all 4 byte for type
			state = recv_buf[7];
		}

        // [H6] kevin, after controller sends a flowmod, client disconnects right away and then controller sends a empty message  with 0 length payload multiple times.
        // [H7] kevin, handle disconnection from controller correctly
        if(!len){
            printf("[ERROR] Controller has closed the connection ...\n");
            is_connected = 0;
            close(client_sockfd);

            // [H37]
            goto reconnect;

       } // end if
		
		switch(state){
		case SFP_HELLO:
			printf("[receive] hello message from controller type: %d\n", state);
			break;

		case SFP_INFO_REQUEST:
			printf("[receive] info request message from controller type: %d\n", state);
			memset(&sfp_info_reply, 0, sizeof(sfp_info_reply));
			// initial spf_header and host_info
			initial_sfp_info_reply(&sfp_info_reply, &header, &hinfo);
    		send(client_sockfd, (char *)&sfp_info_reply, sizeof(sfp_info_reply), 0);
			printf("[send] info reply.\n");
			break;

		case SFP_FLOW_MOD:
			//insert flow rule into table: netlink
			printf("[receive] flow mode message from controller len:%d\n", len);
	
            p = recv_buf;
            message_len = byte4toi(p, 4);        
            printf("message_len:%u\n", message_len);
            p = p + 4;
            message_type = byte4toi(p, 4);        
            printf("message_type:%u\n", message_type);
            p = p + 4;
            message_xid = byte4toi(p, 4);        
            printf("message_xid:%u\n", message_xid);
            p = p + 4;
            message_flowmod_type = byte4toi(p, 4);        
            printf("message_flowmod_type:%u\n", message_flowmod_type);
            p = p + 4;
            message_srctype = byte4toi(p, 4);        
            printf("message_srctype:%u\n", message_srctype);
            p = p + 4;
            message_srclen = byte4toi(p, 4);        
            printf("message_srclen:%u\n", message_srclen);
            p = p + 4;
            message_pid = byte4toi(p, 4);        
            printf("message_pid:%u\n", message_pid);
            p = p + 4;

            // [H10] kevin, variable length src/dst name required
            //memcpy(message_srcname, p, 20);
            memcpy(message_srcname, p, message_srclen);
            // [H10] kevin, variable length src/dst name required
			//for(i = 0; i < 20; i++){
			for(i = 0; i < message_srclen; i++){
                printf("%02x ", *((unsigned char *)message_srcname+i));
			}
            // kevin, print src_name for debugging
            // [H10] kevin, variable length src/dst name required
            printf("\n src_name: ");
			//for(i = 0; i < 20; i++){
			for(i = 0; i < message_srclen; i++){
                printf("%c", *((unsigned char *)message_srcname+i));
			}
            printf("\n");
            // [H10] kevin, variable length src/dst name required
            //p = p + 20;
            p = p + message_srclen;

            message_dsttype = byte4toi(p, 4);        
            printf("message_dsttype:%u\n", message_dsttype);
            p = p + 4;
            message_dstlen = byte4toi(p, 4);        
            printf("message_dstlen:%u\n", message_dstlen);
            p = p + 4;
            message_uuid = byte4toi(p, 4);        
            printf("message_uuid:%u\n", message_uuid);
            p = p + 4;
            message_inode = byte4toi(p, 4);        
            printf("message_inode:%u\n", message_inode);
            p = p + 4;
            // [H10] kevin, variable length src/dst name required
            //memcpy(message_dstname, p, 20);
            memcpy(message_dstname, p, message_dstlen);

            // logic moved to [H9]
            /*
            parsed_inode = getInodeFromFileName(message_dstname);
            printf("parse_inode:%d\n", parsed_inode);
            // [H26] kevin, use adjusted inode number and PID
            // logic moved to [H9]
            message_inode = parsed_inode;
            */
            
            // logic moved to [H9]
            /*
            memset(parsed_pids, 0, 100);
            parsed_num = getPIDFromTaskName(message_srcname, parsed_pids);
            printf("parse_num:%d\n", parsed_num);
            for(i = 0; i < parsed_num; i++) {
                printf("parsed_pids:%d\n", parsed_pids[i]);
            }
            */

            // [H10] kevin, variable length src/dst name required
			//for(i = 0; i < 20; i++){
			for(i = 0; i < message_dstlen; i++){
                printf("%02x ", *((unsigned char *)message_dstname+i));
			}
            // kevin, print dst_name for debugging
            // [H10] kevin, variable length src/dst name required
            printf("\n dst_name: ");
			//for(i = 0; i < 20; i++){
			for(i = 0; i < message_dstlen; i++){
                printf("%c", *((unsigned char *)message_dstname+i));
			}

            printf("\n");
            // [H10] kevin, variable length src/dst name required
            //p = p + 20;
            p = p + message_dstlen;

            message_mask = byte4toi(p, 4);        
            printf("message_mask:%u\n", message_mask);
            p = p + 4;
            message_opcode = byte4toi(p, 4);        
            printf("message_opcode:%u\n", message_opcode);
            p = p + 4;
            message_priority = byte4toi(p, 4);        
            printf("message_priority:%u\n", message_priority);
            p = p + 4;

            // [H9] kevin, dst type should be handled acording to definitions. priority is not passed to flowtable.
            // FIXME: 
            //          ------------------ src type ----------------------------------------------------
            //          1. if src type is SFP_MATCH_ID (0), then use src pid as a valid 
            //          2. if src type is SFP_MATCH_NAME (1), then extract pid from src_name  
            //          3. if src type is SFP_MATCH_REGEX (2), then treat src_name as a string of regex
            //          4. if src type is SFP_SOCKET (3), then treat src_name as a string of IP address
            //          ------------------ dst type ----------------------------------------------------
            //          1. if dst type is SFP_MATCH_ID (0), then verify dst file id {uuid, inode#) 
            //          2. if dst type is SFP_MATCH_NAME (1), then extract dst file id {uuid, inode#} here
            //          3. if dst type is SFP_REGEX (2), then treat dst_name as a string of regex
            //          4. if dst type is SFP_SOCKET (3), then treat dst_name as a string of IP address
            //          ------------------ priority ----------------------------------------------------
            //          there is no priority member in utok_info that should be passed to flow table
            // match.src type
            if(SFP_MATCH_ID == message_srctype){
                // FIXME: check if src pid is valid here
            }
            else if(SFP_MATCH_NAME == message_srctype){
                // extract pid from src_name here
                memset(parsed_pids, 0, 100);
                parsed_num = getPIDFromTaskName(message_srcname, parsed_pids);
                printf("parse_num:%d\n", parsed_num);
                for(i = 0; i < parsed_num; i++) {
                    printf("parsed_pids:%d\n", parsed_pids[i]);
                }
                // FIXME: be careful to handle pid if multiple results returned from getPIDFromTaskName
                message_pid = parsed_pids[0];
   
            }
            else if(SFP_MATCH_REGEX == message_srctype){
                // src_name is used as a string of regex
                // FIXME: parse regex here  
            }
            else if(SFP_MATCH_SOCKET == message_srctype){
                // src_name is used as a string of IP address
            }
            else{
                printf("[ERROR] Undefined src match type \n");
            }
            // match.dst type
            if(SFP_MATCH_ID == message_dsttype){
                // FIXME: verify dst file id {uuid, inode#) 
            }
            else if(SFP_MATCH_NAME == message_dsttype){
                // extract file id {uuid, inode#} from dst_name here

                // inode# 
                parsed_inode = getInodeFromFileName(message_dstname);
                printf("parse_inode:%d\n", parsed_inode);
                message_inode = parsed_inode;
            }
            else if(SFP_MATCH_REGEX == message_dsttype){
                // src_name is used as a string of regex
                // FIXME: parse regex here  
            }
            else if(SFP_MATCH_SOCKET == message_dsttype){
                // src_name is used as a string of IP address
            }
            else{
                printf("[ERROR] Undefined dst match type \n");
            }

            message_action_num = byte4toi(p, 4);        
            printf("message_action_num:%u\n", message_action_num);

            p = p + 4;
            action_ptr = p;
            
            paction = (struct parsed_action *)malloc(sizeof(struct parsed_action)*message_action_num);
            
            for(i = 0; i < message_action_num; i++) { 
                //ptr = (unsigned char *)malloc(byte4toi(p+4, 4)-8);    // [H25]
                paction[i].type = byte4toi(p,4);
                paction[i].len = byte4toi(p+4,4);       // kevin, length of action code

                ptr = (unsigned char *)malloc(paction[i].len);  // [H25] fix seg fault from action andling

                // [H1] kevin, action_len is missing type and len when storing to pass_info->action_buffer for netlink
                //action_len = action_len + paction[i].len;
                
                // [H12] kevin, action_len should be the total number of actions
                //action_len = sizeof(paction[i].type) + sizeof(paction[i].len) + paction[i].len; 
                action_len += sizeof(paction[i].type) + sizeof(paction[i].len) + paction[i].len; 
                
                // [H14] kevin, action_len should have only the length of action code not type and len
                //memcpy(ptr, p+8, byte4toi(p+4, 4)-8);
                memcpy(ptr, p+8, paction[i].len );              // copy action code 
                paction[i].content = ptr;

                printf("ptr:");
                // [H2] kevin, prevent modifying i
			    //for(j = 0; j < byte4toi(p+4, 4)-8; j++){
                //[H13] kevin, wrong action code length is used
			    //for(j = 0; j < byte4toi(p+4, 4)-8; j++){
			    for(j = 0; j < paction[i].len; j++){
                    printf("%02x ", *((unsigned char *)ptr+j));
			    }
                printf("\n");
                // kevin, print all the actions for debugging
                printf("action[%d].type: %d, action[%d].len: %d\n", i, paction[i].type, i, paction[i].len);
                printf("action[%d].data: ", i);
                //[H13] kevin, wrong action code length is used
			    //for(j = 0; j < byte4toi(p+4, 4)-8; j++){
			    for(j = 0; j < paction[i].len; j++){
                    printf("%c", *((unsigned char *)ptr+j));
			    }
                printf("\n");
                // [H14] kevin, action_len should have only the length of action code not type and len
                //p = p + byte4toi(p+4, 4);
                // [H25]
                p += sizeof(paction[i].type) + sizeof(paction[i].len) + paction[i].len; 
           }

            pass_info = (struct utok_info *) malloc(sizeof(struct utok_info));

            // [H20] new struct for utok_info
            /*
            pass_info->msg_type = message_type;                 //[H11] kevin, msg/flowmod type and priority are missing in utok_info struct
            pass_info->sub_type = message_flowmod_type;     //[H11] kevin, msg/flowmod type and priority are missing in utok_info struct
            pass_info->xid = message_xid;

            // [H9][H19]
            //pass_info->pid = message_pid;
            //pass_info->opcode = message_opcode;
            //pass_info->mask = message_mask;
            //pass_info->fid.uuid = message_uuid;
            //pass_info->fid.inode_num = message_inode;
            
            pass_info->match.src_type = message_srctype;
            pass_info->match.src_len = message_srclen;
            pass_info->match.pid = message_pid;
            memcpy(pass_info->match.src_name, message_srcname, message_srclen);
            pass_info->match.dst_type = message_dsttype;
            pass_info->match.dst_len = message_dstlen;
            pass_info->match.fid.uuid = message_uuid;
            pass_info->match.fid.inode_num = message_inode;
            memcpy(pass_info->match.dst_name, message_dstname, message_dstlen);
            pass_info->match.mask = message_mask;
            pass_info->match.opcode = message_opcode;

            pass_info->priority = message_priority;             //[H11] kevin, msg/flowmod type and priority are missing in utok_info struct



            pass_info->action_num = message_action_num;

            //memset(pass_info->action_buffer, 0, 100);           // [H15] kevin, FIXME: should use a reasonable defined constant value
            memset(pass_info->action_buffer, 0, UTOK_MAX_ACTION_BUFFER);           // [H15] kevin, FIXME: should use a reasonable defined constant value
            memcpy(pass_info->action_buffer, action_ptr, action_len);
            */

            pass_info->header.length = message_len;
            pass_info->header.type = message_type;
            pass_info->header.xid = message_xid;

            pass_info->protocol.flowmod.type = message_flowmod_type;
            pass_info->protocol.flowmod.match.src_type = message_srctype;
            pass_info->protocol.flowmod.match.src_len = message_srclen;
            pass_info->protocol.flowmod.match.pid = message_pid;
            memset(pass_info->protocol.flowmod.match.src_name, 0, SFPFM_MAX_NAME);
            memcpy(pass_info->protocol.flowmod.match.src_name, message_srcname, message_srclen);
            pass_info->protocol.flowmod.match.dst_type = message_dsttype;
            pass_info->protocol.flowmod.match.dst_len = message_dstlen;
            pass_info->protocol.flowmod.match.fid.uuid = message_uuid;
            pass_info->protocol.flowmod.match.fid.inode_num = message_inode;
            memset(pass_info->protocol.flowmod.match.dst_name, 0, SFPFM_MAX_NAME);
            memcpy(pass_info->protocol.flowmod.match.dst_name, message_dstname, message_dstlen);
            pass_info->protocol.flowmod.match.mask = message_mask;
            pass_info->protocol.flowmod.match.opcode = message_opcode;

            pass_info->protocol.flowmod.priority = message_priority;          
            pass_info->protocol.flowmod.action_num = message_action_num;

            memset(pass_info->protocol.flowmod.action_buffer, 0, UTOK_MAX_ACTION_BUFFER); 
            memcpy(pass_info->protocol.flowmod.action_buffer, action_ptr, action_len);      // [H21] kevin, note: action type and len are not coverted to host order


			sock_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_USER);
			if(sock_fd < 0){
                printf("[ERROR] fail to create netlink socket\n");      // kevin, debugging
				return -1;
            }

			memset(&src_addr, 0, sizeof(src_addr));
			src_addr.nl_family = AF_NETLINK;
			src_addr.nl_pid = getpid(); //self pid

			bind(sock_fd, (struct sockaddr*)&src_addr, sizeof(src_addr));

			memset(&dest_addr, 0, sizeof(dest_addr));
			dest_addr.nl_family = AF_NETLINK;
			dest_addr.nl_pid = 0; //For Linux Kernel
			dest_addr.nl_groups = 0; // unicast

			nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
			memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
			nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
			nlh->nlmsg_pid = getpid();
			nlh->nlmsg_flags = 0;
			
			memcpy(NLMSG_DATA(nlh), (unsigned char *)pass_info, sizeof(struct utok_info));
			printf("utok_info:");
            
            for(i = 0; i < sizeof(struct utok_info); i++){
                printf("%02x ", *((unsigned char *)NLMSG_DATA(nlh)+i));
			}
            // kevin, debugging 
            /*
            printf("utok_info.msg_type = %d \n", pass_info->msg_type);
            printf("utok_info.flowmod_type = %d \n", pass_info->sub_type);
            printf("utok_info.xid = %d \n", pass_info->xid); // [20]

            // [H9][H19]
            //printf("utok_info.pid = %d \n", pass_info->pid);
            //printf("utok_info.opcode = %d \n", pass_info->opcode);
            //printf("utok_info.mask = %x \n", pass_info->mask);
            //printf("utok_info.fid.uuid = %d \n", pass_info->fid.uuid);
            //printf("utok_info.fid.inode_num = %d \n", pass_info->fid.inode_num);
            
            printf("utok_info.match.src_type = %d \n", pass_info->match.src_type);
            printf("utok_info.match.src_len = %d \n", pass_info->match.src_len);
            printf("utok_info.match.pid = %d \n", pass_info->match.pid);
            printf("utok_info.match.src_name = %d \n", pass_info->match.src_name);
            printf("utok_info.match.dst_type = %d \n", pass_info->match.dst_type);
            printf("utok_info.match.dst_len = %d \n", pass_info->match.dst_len);
            printf("utok_info.match.fid.uuid = %d \n", pass_info->match.fid.uuid);
            printf("utok_info.match.fid.inode_num = %d \n", pass_info->match.fid.inode_num);
            printf("utok_info.match.dst_name = %d \n", pass_info->match.dst_name);
            printf("utok_info.match.mask = %d \n", pass_info->match.mask);
            printf("utok_info.match.opcode = %d \n", pass_info->match.opcode);



            printf("utok_info.priority = %d \n", pass_info->priority);
            printf("utok_info.action_num = %d \n", pass_info->action_num);
            */
			printf("\n");

			iov.iov_base = (void *)nlh;
			iov.iov_len = nlh->nlmsg_len;
			msg.msg_name = (void *)&dest_addr;
			msg.msg_namelen = sizeof(dest_addr);
			msg.msg_iov = &iov;
			msg.msg_iovlen = 1;

			printf("UserSpace:Sending Flow Mod message to kernel\n");
			sendmsg(sock_fd,&msg,0);

            // [H22] kevin, FIXME: return message from the kernel should be non-blocking
			// Read ack message from kernel
			recvmsg(sock_fd, &msg, 0);
			printf("UserSpace:insert finished\n");

			close(sock_fd);

            // [Jianwei] clean src_name & dst_name in pass_info
            memset(pass_info->protocol.flowmod.match.src_name, 0, SFPFM_MAX_NAME);
            memset(pass_info->protocol.flowmod.match.dst_name, 0, SFPFM_MAX_NAME);

            if(pass_info)
                free(pass_info);
            pass_info = NULL;                           // kevin, intialize
            
            for(i = 0; i < message_action_num; i++){
                free(paction[i].content);
                paction[i].content = NULL;              // kevin, initialize
            }
            if(paction)
                free(paction); 
            paction = NULL;                             // kevin, initialize
			break;
	
        case SFP_FLOW_STATE_REQUEST:
            printf("[receive] flow state request message.\n");

            p = recv_buf;
            
            //[H17] kevin, fix stats reply in terms of variable length src/dst name
            // extracts flow state request
            memset(&stats_request, 0, sizeof(stats_request));
            
            // header 
            stats_request.header.length = byte4toi(p,4);
            p += 4;
            stats_request.header.type = byte4toi(p,4);
            p += 4;
            stats_request.header.xid = byte4toi(p,4);
            p += 4;

            // match src
            stats_request.match.src_type = byte4toi(p,4);
            p += 4;
            stats_request.match.src_len = byte4toi(p,4);
            p += 4;
            stats_request.match.pid = byte4toi(p,4);
            p += 4;
            memcpy(stats_request.match.src_name, p, stats_request.match.src_len);
            p += stats_request.match.src_len;
           
            // match dst
            stats_request.match.dst_type = byte4toi(p,4);
            p += 4;
            stats_request.match.dst_len = byte4toi(p,4);
            p += 4;
            stats_request.match.fid.uuid = byte4toi(p,4);
            p += 4;
            stats_request.match.fid.inode_num = byte4toi(p,4);
            p += 4;
            memcpy(stats_request.match.dst_name, p, stats_request.match.dst_len);
            p += stats_request.match.dst_len;

            stats_request.match.mask = byte4toi(p,4);
            p += 4;
            stats_request.match.opcode = byte4toi(p,4);
            p += 4;
            // [H35]
            // [H9] kevin, dst type should be handled acording to definitions. priority is not passed to flowtable.
            // FIXME: 
            //          ------------------ src type ----------------------------------------------------
            //          1. if src type is SFP_MATCH_ID (0), then use src pid as a valid 
            //          2. if src type is SFP_MATCH_NAME (1), then extract pid from src_name  
            //          3. if src type is SFP_MATCH_REGEX (2), then treat src_name as a string of regex
            //          4. if src type is SFP_SOCKET (3), then treat src_name as a string of IP address
            //          ------------------ dst type ----------------------------------------------------
            //          1. if dst type is SFP_MATCH_ID (0), then verify dst file id {uuid, inode#) 
            //          2. if dst type is SFP_MATCH_NAME (1), then extract dst file id {uuid, inode#} here
            //          3. if dst type is SFP_REGEX (2), then treat dst_name as a string of regex
            //          4. if dst type is SFP_SOCKET (3), then treat dst_name as a string of IP address
            //          ------------------ priority ----------------------------------------------------
            //          there is no priority member in utok_info that should be passed to flow table
            // match.src type
            if(SFP_MATCH_ID == stats_request.match.src_type ){
                // FIXME: check if src pid is valid here
            }
            else if(SFP_MATCH_NAME == stats_request.match.src_type ){
                // extract pid from src_name here
                memset(parsed_pids, 0, 100);
                parsed_num = getPIDFromTaskName(stats_request.match.src_name , parsed_pids);
                printf("parse_num:%d\n", parsed_num);
                for(i = 0; i < parsed_num; i++) {
                    printf("parsed_pids:%d\n", parsed_pids[i]);
                }
                // FIXME: be careful to handle pid if multiple results returned from getPIDFromTaskName
                stats_request.match.pid = parsed_pids[0];

   
            }
            else if(SFP_MATCH_REGEX == stats_request.match.src_type ){
                // src_name is used as a string of regex
                // FIXME: parse regex here  
            }
            else if(SFP_MATCH_SOCKET == stats_request.match.src_type ){
                // src_name is used as a string of IP address
            }
            else{
                printf("[ERROR] Undefined src match type \n");
            }
            // match.dst type
            if(SFP_MATCH_ID == stats_request.match.dst_type ){
                // FIXME: verify dst file id {uuid, inode#) 
            }
            else if(SFP_MATCH_NAME == stats_request.match.dst_type ){
                // extract file id {uuid, inode#} from dst_name here

                // inode# 
                parsed_inode = getInodeFromFileName(stats_request.match.dst_name );
                printf("parse_inode:%d\n", parsed_inode);
                stats_request.match.fid.inode_num = parsed_inode;
            }
            else if(SFP_MATCH_REGEX == stats_request.match.dst_type ){
                // src_name is used as a string of regex
                // FIXME: parse regex here  
            }
            else if(SFP_MATCH_SOCKET == stats_request.match.dst_type ){
                // src_name is used as a string of IP address
            }
            else{
                printf("[ERROR] Undefined dst match type \n");
            }


            /*
            memset(&stats_reply, 0, sizeof(stats_reply));
            stats_reply.header.length = 96;
            stats_reply.header.type = 5;
            stats_reply.header.xid = p_stats_request->header.xid;

            stats_reply.match.src_type  = p_stats_request->match.src_type;
            stats_reply.match.src_len   = p_stats_request->match.src_len;
            stats_reply.match.pid       = p_stats_request->match.pid;
            //stats_reply.match.src_name  = p_stats_request->match.src_name;
            memcpy(stats_reply.match.src_name, p_stats_request->match.src_name, 20);
            stats_reply.match.dst_type  = p_stats_request->match.dst_type;
            stats_reply.match.dst_len   = p_stats_request->match.dst_len;
            stats_reply.match.fid.uuid  = p_stats_request->match.fid.uuid;
            stats_reply.match.fid.inode_num = p_stats_request->match.fid.inode_num;
            //stats_reply.match.dst_name  =  p_stats_request->match.dst_name;
            memcpy(stats_reply.match.dst_name, p_stats_request->match.dst_name, 20);
            stats_reply.match.mask      =  p_stats_request->match.mask;

            // TODO: need to get the hits from manager through netlink
            stats_reply.event_hits = 123;
            stats_reply.byte_hits = 321;
            */

            // [H16] kevin, FIXME: stats reply message raises an exception in the controller
            //send(client_sockfd, (char *)&stats_reply, sizeof(stats_reply), 0);


            // prepare netlink message
            pass_info = (struct utok_info *) malloc(sizeof(struct utok_info));

            memcpy(&pass_info->header, &stats_request.header, sizeof(struct sfp_header));
            memcpy(&pass_info->protocol.statsreq, &stats_request.match, sizeof(struct sfp_match)); 
            
            // prepare netlink socket
            sock_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_USER);
			if(sock_fd < 0){
                printf("[ERROR] fail to create netlink socket\n");      
				return -1;
            }

			memset(&src_addr, 0, sizeof(src_addr));
			src_addr.nl_family = AF_NETLINK;
			src_addr.nl_pid = getpid(); //self pid

			bind(sock_fd, (struct sockaddr*)&src_addr, sizeof(src_addr));

			memset(&dest_addr, 0, sizeof(dest_addr));
			dest_addr.nl_family = AF_NETLINK;
			dest_addr.nl_pid = 0; //For Linux Kernel
			dest_addr.nl_groups = 0; // unicast

			nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
			memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
			nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
			nlh->nlmsg_pid = getpid();
			nlh->nlmsg_flags = 0;
			
			memcpy(NLMSG_DATA(nlh), (unsigned char *)pass_info, sizeof(struct utok_info));
			printf("utok_info:");
            
            for(i = 0; i < sizeof(struct utok_info); i++){
                printf("%02x ", *((unsigned char *)NLMSG_DATA(nlh)+i));
			}
            printf("\n");
            
            // nl msg setup
			iov.iov_base = (void *)nlh;
			iov.iov_len = nlh->nlmsg_len;
			msg.msg_name = (void *)&dest_addr;
			msg.msg_namelen = sizeof(dest_addr);
			msg.msg_iov = &iov;
			msg.msg_iovlen = 1;

			printf("UserSpace: Sending Flow State Request to kernel\n");
			sendmsg(sock_fd,&msg,0);

            // [H22] kevin, FIXME: return message from the kernel should be non-blocking
			// read results from kernel  
			recvmsg(sock_fd, &msg, 0);
			printf("UserSpace: Received Flow State Report from kernel\n");

            memcpy(&stats_reply, NLMSG_DATA(nlh), sizeof(struct sfp_flow_stats_reply));
			close(sock_fd); // close nl socket

            printf("------------- Flow Stats Reply -------------------\n");
            printf("Header (type: %d, length: %d, xid: %d \n", stats_reply.header.type, stats_reply.header.length, stats_reply.header.xid);
            printf("Event hits: %d, Byte hits: %d \n", stats_reply.event_hits, stats_reply.byte_hits);
            
            // send flow stats report to controller
            // [H23] kevin, FIXME: use network byte order when sending packets to controller
            send_buf_len = netorder_sfp_flow_stats_reply(&stats_reply, send_buf);

            printf("Send buf len: %d \n", send_buf_len);

            // [H32] kevin, fix send buffer length
            //send(client_sockfd, (char *)send_buf, sizeof(struct sfp_flow_stats_reply), 0);

            // [H34]
            send(client_sockfd, (char *)send_buf, send_buf_len, 0);


            // ------------------------------------------------------------
            // test code sending an action report message to controller
            
            /*
            test_actreport.header.type = SFP_ACTION_REPORT;
            send_buf_len = netorder_sfp_action_report(&test_actreport, send_buf);

            printf("Test Sending an action report to controller... )\n");
            printf("ACTION Send buf len: %d \n", send_buf_len);
            ret = send(client_sockfd, (char *)send_buf, send_buf_len, 0);
            printf("Result: %d\n", ret);
           */ 


            if(pass_info)
                free(pass_info);
            pass_info = NULL;                           // kevin, intialize

            break;
            
        /*    
         *    
		case SFP_FLOW_STATE_REPORT:
			printf("[send] flow state report message\n");
			//Test State Report
            memset(&flow_report, 0, sizeof(flow_report));
            //initial spf_header and host_info
            //initial_sfp_flow_report();
            flow_report.header.length = 92;
            flow_report.header.type = 3;
            flow_report.header.xid = 0;
            send(client_sockfd, (char *)&flow_report, sizeof(flow_report), 0);
			break;
		*/

        // [H8] kevin, echo message
        case SFP_ECHO_REQUEST:
            p_sfp_header = (struct sfp_header*)&recv_buf;
            printf("[recv] Echo request, xid: %d \n", p_sfp_header->xid);
            memset(&echo_msg, 0, sizeof(echo_msg));
            initial_sfp_echo_reply(&echo_msg, p_sfp_header->xid);

            printf("[send] Echo reply, xid: %d \n", echo_msg.header.xid);
            send(client_sockfd, (char *)&echo_msg, sizeof(echo_msg), 0);
            break;
        case SFP_ECHO_REPLY:
            // do nothing
            break;

        }
		
    }
    close(client_sockfd);
    return 0;  
}  

int main(int argc, char *argv[]){
    char *host_string, *port_string;
    if (argc < 3) {
	    printLog("Usage: client host port [-d].\n");
	    return 1;
    }

    host_string = argv[1];
    port_string = argv[2];

    if(argc == 4 && strcmp(argv[3], "-d") == 0) {
        daemon_status = 1;
    }

    if(daemon_status == 1){
        daemon(1, 0);
    }

    printf("host_s: %s, port_s:%s\n", host_string, port_string);
    client_main(host_string, port_string);
}
