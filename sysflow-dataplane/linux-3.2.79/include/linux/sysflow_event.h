#ifndef SYSFLOW_EVENT_H
#define SYSFLOW_EVENT_H 1

#define SFPFM_MAX_NAME  256

/* sysflow source object type*/
#define SYSFLOW_SRC_UNKNOWN		-1
#define SYSFLOW_SRC_PROCESS		0
#define SYSFLOW_SRC_SOCKET	 	1

/* sysflow destination object type*/
#define SYSFLOW_DST_UNKNOWN		-1
#define SYSFLOW_DST_FILE		0
#define SYSFLOW_DST_SOCKET		1


/* sysflow system event operation ID*/
#define SYSFLOW_OP_UNKNOWN	 	-1
#define SYSFLOW_FILE_IOCTL	 	0	/*file operation*/
#define SYSFLOW_FILE_READ	 	1
#define SYSFLOW_FILE_WRITE	 	2
#define SYSFLOW_FILE_APPEND	 	3
#define SYSFLOW_FILE_CREATE	 	4
#define SYSFLOW_FILE_GETATTR 	5
#define SYSFLOW_FILE_SETATTR 	6
#define SYSFLOW_FILE_LOCK	 	7
#define SYSFLOW_FILE_LINK	 	8
#define SYSFLOW_FILE_EXECUTE 	9
#define SYSFLOW_FILE_RENAME	 	10
#define SYSFLOW_FILE_OPEN       11

#define SYSFLOW_SOCKET_IOCTL       12 /*socket operations*/
#define SYSFLOW_SOCKET_READ        13
#define SYSFLOW_SOCKET_WRITE       14
#define SYSFLOW_SOCKET_APPEND      15
#define SYSFLOW_SOCKET_CREATE      16
#define SYSFLOW_SOCKET_GETATTR     17
#define SYSFLOW_SOCKET_SETATTR     18
#define SYSFLOW_SOCKET_CONNECT     19
#define SYSFLOW_SOCKET_LISTEN      20

#define SYSFLOW_IPC_IOCTL       21 /*ipc operations*/
#define SYSFLOW_IPC_READ        22
#define SYSFLOW_IPC_WRITE       23
#define SYSFLOW_IPC_APPEND      24
#define SYSFLOW_IPC_CREATE      25
#define SYSFLOW_IPC_GETATTR     26	
#define SYSFLOW_IPC_SETATTR     27

#define SYSFLOW_INODE_CREATE    28
#define SYSFLOW_SYMLINK_CREATE  29
#define SYSFLOW_LINK_CREATE     30
#define SYSFLOW_DIR_CREATE  	31
#define SYSFLOW_DEV_INODE_CREATE	32
#define SYSFLOW_UNLINK 			33
#define SYSFLOW_DIR_REMOVE 		34
#define SYSFLOW_FILE_MMAP       35
#define SYSFLOW_MSG_MSG_FREE    36
#define SYSFLOW_MSG_MSG_ALLOC   37
#define SYSFLOW_MSG_QUEUE_FREE  38
#define SYSFLOW_MSG_QUEUE_ALLOC 39
#define SYSFLOW_MSG_QUEUE_SND   40
#define SYSFLOW_MSG_QUEUE_RCV   41
#define SYSFLOW_MSG_QUEUE_CTL   42
#define SYSFLOW_FILE_FCNTL      43
#define SYSFLOW_DENTRY_OPEN     44


struct file_id {
    uint32_t uuid;
	uint32_t inode_num;
};


struct sysflow_system_event_hdr{
	int src_type;		/*The type for source object*/
	int dst_type;		/*The type for destination object*/
	int opcode;			/*The operation code for system event*/
	
	union{
		int pid;
	};	
	union{
		struct file_id fid;
	};
	char src_name[SFPFM_MAX_NAME];
	char dst_name[SFPFM_MAX_NAME];
 	
};

struct sysflow_system_event{
	int len;		/*the total length of system event*/
	struct sysflow_system_event_hdr *hdr;
	char *payload;
};


#endif /* sysflow_event.h */
