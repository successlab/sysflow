package sysflow_controller.apps;

import java.io.PrintStream;
import java.nio.ByteBuffer;

import sysflow_controller.core.SysFlowMessageListener;
import sysflow_controller.message.FlowModMessage;
import sysflow_controller.message.SFMessage;
import sysflow_controller.timer.sf_timer;
import sysflow_controller.types.HostID;
import sysflow_controller.types.sf_action;
import sysflow_controller.types.sf_host;
import sysflow_controller.types.sf_mask;
import sysflow_controller.types.sf_type_match;
import sysflow_controller.types.sf_type_message;
import sysflow_controller.types.sf_type_operation;

public class chacl implements SysFlowMessageListener {

	//String client_host = "10.0.0.1";
	
	//String client_host = "10.229.216.135";
	
	String client_host = "10.0.2.4";
	
	//String client_host = "10.228.226.176";
	
	//String client_host = "192.168.0.104";
	
	String client_host2 = "10.229.216.135";

	//String server_host = "10.0.0.2";
	String server_host = "10.228.226.176";

	String client_proc = "client";

	String server_proc = "server";

	Integer tag_non_admin = 111;

	@Override
	public void handleIncomingMessage(sf_host host, SFMessage message) {
		if ((message.getType() == sf_type_message.SFP_INFO_REPLY)) {
			System.out.println("*** Enter cross host access control program ***");
			installACL(host);
		}
	}

	@Override
	public void handleOutgoingMessage(sf_host host, SFMessage message) {

	}

	private void installACL(sf_host host) {
		//install encode 
		System.out.println("Current Host ID: " + host.getHostID() + ", client_host: " + client_host);
		
		// kevin, fix to use correct String for checking client_host IP
		//if (host.getHostID().equals(client_host)) {
		if (host.getHostID().getHostID().equals(client_host)) {	

			FlowModMessage flowMod1 = new FlowModMessage(FlowModMessage.SFPFM_ADD, 1, new sf_mask(true,
					true, true, true, false).getMask(),
					sf_type_operation.SYSFLOW_SOCKET_WRITE);
			int pid = 1001;
			flowMod1.setSource(sf_type_match.SFP_MATCH_NAME,
					client_proc.length(), pid, client_proc.toCharArray());
			int inode = 2;
			int uuid = 3;
			flowMod1.setDestination(sf_type_match.SFP_MATCH_SOCKET, 0, uuid,
					inode, null);
			flowMod1.addAction(new sf_action(sf_action.SYSFLOW_ACTION_DECODE,
					ByteBuffer.allocate(4).putInt(tag_non_admin).array(), 4));

			System.out.println("----------- ACL for client -----------");
			
			//host.sendMsg(flowMod1);
			
			// kevin, the existing timer runs incorrectly, which executes a task infinitely once fired.
			/*
			// schedule the flow rule at 5:00 pm
			sf_timer timer1 = new sf_timer(host, flowMod1);
			timer1.startExecutionAt(17, 0, 0);
			*/
			
			// schedule the flow rule at 5:00 pm every day
			String execName = new String("CHACL-App");
			sf_timer timer1 = new sf_timer(execName, host, flowMod1);
			timer1.startExecutionAt(12, 46, 0);
			
		}

		// kevin, fix to use correct String for checking server_host IP
		//if (host.getHostID().equals(server_host)) {
		if (host.getHostID().getHostID().equals(server_host)) {
			FlowModMessage flowMod2 = new FlowModMessage(FlowModMessage.SFPFM_ADD, 1, new sf_mask(true,
					true, true, true, false).getMask(),
					sf_type_operation.SYSFLOW_SOCKET_READ);
			int pid = 1001;
			flowMod2.setSource(sf_type_match.SFP_MATCH_NAME,
					server_proc.length(), 1001, server_proc.toCharArray());
			int inode = 2;
			int uuid = 3;
			flowMod2.setDestination(sf_type_match.SFP_MATCH_SOCKET, 0, uuid,
					inode, null);
			flowMod2.addAction(new sf_action(sf_action.SYSFLOW_ACTION_DECODE,
					ByteBuffer.allocate(4).putInt(tag_non_admin).array(), 4));
			flowMod2.addAction(new sf_action(sf_action.SYSFLOW_ACTION_DENY,
					null, 0));
			
			System.out.println("----------- ACL for server -----------");
			
			// kevin, the existing timer runs incorrectly, which executes a task infinitely once fired.
			/*
			sf_timer timer2 = new sf_timer(host, flowMod2);
			timer2.startExecutionAt(17, 0, 0);
			*/
			
			String execName = new String("CHACL-App");
			sf_timer timer2 = new sf_timer(execName, host, flowMod2);
			timer2.startExecutionAt(13, 47, 0);
		}
	}
}
