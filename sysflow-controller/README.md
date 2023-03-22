# sysflow-controller

## Introduction
sysflow-controller is the controller implementation of sysflow, which provides management interfaces to administrators.

## Requirement

### For User
* JRE(1.8 or higher version)

### For Developer
* JDK(1.8 or higher version)
* Eclipse or IDEA

## Usage

### For User
1. Download the pre-compiled jar file in <strong>target</strong>.
2. Execute `java -jar sysflowController.jar` to run it. The controller will start listening at port 7766.
// TODO: add arguments for users

### For Developer
1. Clone the repository.
2. Load the project in Eclipse or IDEA.
3. Open `src/sysflow_controller/core/SysFlowControllerImpl.java` or you can also implement and run your own controller implementation. You may change the listening port and configuration of applications now.
4. Run the main method in the class.

## How to extend
### Build your own controller
We provide the interface class of controller called `SysFlowController`. By implement the class, you may build your own controller.

### Add an application
Each application is actually a message listener in our design. All you need to add an application is implement `SysFlowMessageListener` under <strong>package sysflow_controller.apps</strong>. The API we provided is shown in the following table.

| API  | description  | arguments |
|---|---|---|
| handleIncomingMessage | handler of incoming messages, which will be called when the controller receives a message from clients | host: Sender of the message; message: The content of the message |
| handleOutgoingMessage | handler of incoming messages, which will be called when the controller is going to send a message to clients  | host: Receiver of the message; message: The content of the message |

### Add a new message in protocol and customize a field of a message
1. Add a new message type in <strong>class SFMessageType</strong> of <strong>package sysflow_controller.message</strong> as well as in <strong> package sysflow_controller.types </strong>
2. Add a new class that inherits <strong>SFMessage</strong> in <strong>package sysflow_controller.message</strong>. Define a new message on top of a SysFlow header (basic class SFMessageType keeps the header). Override methods from <strong>SFMessage</strong> properly and implement <strong>serialize()</strong>. 
3. Add new message handling code for the new message in <strong>public static SFMessage readFrom(ByteBuf buffer)</strong> of  <strong>SFMessage</strong> as well as in <strong>public static SFMessage getMessageFromSocket(SocketChannel socket, ByteBuffer dataBuffer)</strong>
4. Add a message processing call in <strong>processSFMessage</strong> in <strong>SFChannelHandler</strong> class.
5. Now, you'll be able to have access to incoming and outgoing new message through <strong>handleIncomingMessage()</strong> and <strong>handleOutgoingMessage</strong> in SysFlow applications. 

Add API info for other class in Controller

### Add a sysflow operation
Add your new operation definition in `src/sysflow_controller/types/sf_type_operation.java`.
<strong>NOTE: the number should be defined the same as protocol.h in dataplane.</strong>

### Descriptions of the source tree
| Package | Class | Description
|---|---|---|
| sysflow_controller.apps | class chacl | Cross-Host Access Control List app to install access control policies based on time context|
| sysflow_controller.apps | class cldlp |  Cross-Layer Data Leakage Prevention app to first encode tag into packets for interested system flow (installMonitorFlowRule) and propagate tags among different hosts (installTrackFlowRule)|
| sysflow_controller.apps | class file_reflector | File Reflector app to automate the deployment of decoy resources in the system to lure potential attacks that aim to steal sensitive data from protected resources |
| sysflow_controller.apps | class test_flow_mod | Test Flow Mod message app |
| sysflow_controller.apps | class class test_flow_stat_req | Test Flow Stats Request message app |
||||
| sysflow_controller.core | | Controller core classes to start the controller and manage connections, hosts, messages, etc.|
| sysflow_controller.denifitions | | SysFlow message definitions |
| sysflow_controller.message | | SysFlow message operations |
| sysflow_controller.timer | class sf_timer | Scheduled execution service for applications |
| sysflow_controller.types | | Classes to define types used both in the controller and dataplane |


