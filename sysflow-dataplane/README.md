# sysflow-dataplane

## Introduction
sysflow-dataplane is the implementation of sysflow client for linux.

## Download
Due to the complicated configuration steps to compile the project, we provide a virtual machine which has everything built-in. You may need VMware(14 or higher version) to run it.

[Download Link](https://drive.google.com/open?id=1lDciZlTkTXg4-3qPOhM8rtblza0KcCu0)

## Usage
1. (not needed if you use VM)Compile & install the kernel in linux-3.2.79. You can simply execute `./doit.sh`.
2. (not needed if you use VM)cd to `manager` & Execute `make` to compile the kernel module.
3. (not needed if you use VM)cd to `daemon` & Execute `gcc client.c -o client` to compile the daemon.
4. cd to `manager` & Execute `sudo insmod sysflow.ko` to install the kernel module. You may use `dmesg` to check if it's running correctly. You should be able to see some log start with `[S2OS]`.
5. cd to `daemon`& Execute `./client host_ip host_port [-d]` to run the daemon. `[-d]` is an option, with which the daemon will run as a demon and all the log info will be redirected to `/var/log/sysflow_client.log`.

## How to extend
## Add a new message in protocol and customize a field of a message
### Controller 
1. Add a new message type in <strong>class SFMessageType</strong> of <strong>package sysflow_controller.message</strong> as well as in <strong> package sysflow_controller.types </strong>
2. Add a new class that inherits <strong>SFMessage</strong> in <strong>package sysflow_controller.message</strong>. Define a new message on top of a SysFlow header (basic class SFMessageType keeps the header). Override methods from <strong>SFMessage</strong> properly and implement <strong>serialize()</strong>. 
3. Add new message handling code for the new message in <strong>public static SFMessage readFrom(ByteBuf buffer)</strong> of  <strong>SFMessage</strong> as well as in <strong>public static SFMessage getMessageFromSocket(SocketChannel socket, ByteBuffer dataBuffer)</strong>
4. Add a message processing call in <strong>processSFMessage</strong> in <strong>SFChannelHandler</strong> class.
5. Now, you'll be able to have access to incoming and outgoing new message through <strong>handleIncomingMessage()</strong> and <strong>handleOutgoingMessage</strong> in SysFlow applications. 

### Channel Agent 
1. Add a new message type in <strong>enum sfp_type</strong> in <strong>KERNEL_SRC_DIR/include/linux/protocol.h</strong>
2. Add a definition of the new message naming with the prefix <strong>"sfp_flow_"</strong> in <strong>protoco.h</strong>.
3. Note that every message should include <strong>struct sfp_header</strong> as a first struct member. 
4. Add functions for the message in <strong>chan_agent.c</strong>, for instance, initializing, receiving, sending, parsing, or any other message handling funcitons. 
5. Note not to forget to use a big endian when sending a packet out to the controller.

### Netlink 
1. If a new message needs to reach SysFlow kernel module, it should be defined in the <strong>netlink message format</strong> as well.
2. Add a new message type in <strong>chan_agent.c</strong> if necessary.
3. Add it as a member of <strong>union protocol</strong> in <strong>struct utok_info</strong>.
4. Do (2), (3) in <strong>sysflow.c</strong> in the SysFlow kernel module.
5. Copy the message into a sending, receving buffer through  <strong>NLMSG_DATA(NLHDR)</strong>.




## Add a sysflow operation
1. Add your new operation definition in `include/linux/sysflow_event.h`. <strong>NOTE: the number should be defined the same as in controller.</strong>
2. (option)If you want to use LSM to hook the operation, you may add your code into `security/sample/sample.c`. Add your hook info in `s2os_ops`(its definition is at the bottom of the file).
3. In the hook function, you should create a system event and call `s2os_invoke_sysflow_func` with your event. To simplify the steps, we have a `sample_hook` in `sample.c`. You may just copy it and change the name and arguments.
4. Handle actions you may care based on the return value of `s2os_invoke_sysflow_func`.
  
NOTE: Please free all the memory alloced in the routine before it return. Each system event may be triggered a lot of times per second. Bad memory management may cause memory leak.

## Add a sysflow action
1. Add your new action definition in `include/linux/sysflow.h`. <strong>NOTE: the number should be defined the same as in controller.</strong>
2. Handle the new action where you may care.
