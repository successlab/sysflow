package sysflow_controller.types;

public class sf_type_operation {
	public static final int SYSFLOW_OP_UNKNOWN	=	-1;        		
	public static final int SYSFLOW_FILE_IOCTL	=	0;	/*file operation*/
	public static final int SYSFLOW_FILE_READ	=	1;
	public static final int SYSFLOW_FILE_WRITE	=	2;
	public static final int SYSFLOW_FILE_APPEND	=	3;
	public static final int SYSFLOW_FILE_CREATE	=	4;
	public static final int SYSFLOW_FILE_GETATTR=	5;	
	public static final int SYSFLOW_FILE_SETATTR=	6;
	public static final int SYSFLOW_FILE_LOCK	=	7;
	public static final int SYSFLOW_FILE_LINK	=	8;
	public static final int SYSFLOW_FILE_EXECUTE=	9;
	public static final int SYSFLOW_FILE_RENAME	=	10;
	public static final int SYSFLOW_FILE_OPEN   =   11;
	
	public static final int SYSFLOW_SOCKET_IOCTL   =   12; /*socket operations*/
	public static final int SYSFLOW_SOCKET_READ    =   13;
	public static final int SYSFLOW_SOCKET_WRITE   =   14;
	public static final int SYSFLOW_SOCKET_APPEND  =   15;
	public static final int SYSFLOW_SOCKET_CREATE  =   16;
	public static final int SYSFLOW_SOCKET_GETATTR =   17;	
	public static final int SYSFLOW_SOCKET_SETATTR =   18;
	public static final int SYSFLOW_SOCKET_CONNECT =   19;	
	public static final int SYSFLOW_SOCKET_LISTEN  =   20;


	public static final int SYSFLOW_IPC_IOCTL   =   21; /*ipc operations*/
	public static final int SYSFLOW_IPC_READ    =   22;
	public static final int SYSFLOW_IPC_WRITE   =   23;
	public static final int SYSFLOW_IPC_APPEND  =   24;
	public static final int SYSFLOW_IPC_CREATE  =   25;
	public static final int SYSFLOW_IPC_GETATTR =   26;	
	public static final int SYSFLOW_IPC_SETATTR =   27;

	//TODO: support customized operation types

}

