package sysflow_controller.apps;

import sysflow_controller.core.SysFlowMessageListener;
import sysflow_controller.message.FlowModMessage;
import sysflow_controller.message.FlowStatsReplyMessage;
import sysflow_controller.message.SFMessage;
import sysflow_controller.types.HostID;
import sysflow_controller.types.sf_action;
import sysflow_controller.types.sf_host;
import sysflow_controller.types.sf_mask;
import sysflow_controller.types.sf_type_match;
import sysflow_controller.types.sf_type_message;
import sysflow_controller.types.sf_type_operation;

public class file_reflector implements SysFlowMessageListener {

//	String test_proc = "test";
	
	String protected_file = "/tmp/monitored/sec";
	String decoy_file = "/tmp/decoy.tax";
	
	@Override
	public void handleIncomingMessage(sf_host host, SFMessage message) {
		if ((message.getType() == sf_type_message.SFP_INFO_REPLY)) {
			System.out.println("enter SysFlow message handler of file reflector app.");
			
			System.out.println("Receive message from host: " + host.getHostID().toString());
			
			installRedirectionFlowRule(host);
		}
		// kevin, adds flow stat report handling code
		else if ((message.getType() == sf_type_message.SFP_FLOW_STATE_REPORT)) {
			FlowStatsReplyMessage stats_reply = (FlowStatsReplyMessage) message;
			System.out.println("------------ Flow Stat Report ------------");
			System.out.println(stats_reply);
		}
	}

	@Override
	public void handleOutgoingMessage(sf_host host, SFMessage message) {
	}

	private void installRedirectionFlowRule(sf_host host) {
		FlowModMessage flowMod = new FlowModMessage(FlowModMessage.SFPFM_ADD, 1, new sf_mask(false, true,
				true, false, true).getMask(), sf_type_operation.SYSFLOW_FILE_READ);
		
		int pid = 1001;
		flowMod.setSource(sf_type_match.SFP_MATCH_ID, 0, 1001, null);
		//flowMod.setSource(sf_type_match.SFP_MATCH_NAME, test_proc.length(), pid, test_proc.toCharArray());
		
		
		int inode = 0;
		int uuid = 0;
		flowMod.setDestination(sf_type_match.SFP_MATCH_NAME, protected_file.length() , uuid, inode, protected_file.toCharArray());
		flowMod.addAction(new sf_action(sf_action.SYSFLOW_ACTION_REDIRECT, decoy_file.getBytes(), decoy_file.length()));

		System.out.println("send redirection flow mod message");
		host.sendMsg(flowMod);
	}

}
