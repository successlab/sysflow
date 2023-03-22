package sysflow_controller.apps;

import java.io.IOException;

import sysflow_controller.core.SysFlowMessageListener;
import sysflow_controller.message.FlowStatsReplyMessage;
import sysflow_controller.message.FlowStatsRequestMessage;
import sysflow_controller.message.InfoReplyMessage;
import sysflow_controller.message.SFMessage;
import sysflow_controller.types.sf_host;
import sysflow_controller.types.sf_mask;
import sysflow_controller.types.sf_type_match;
import sysflow_controller.types.sf_type_message;
import sysflow_controller.types.sf_type_operation;

public class test_flow_stat_req implements SysFlowMessageListener {

	// kevin, test
	String protected_file = "/tmp/monitored/sec";
	String src_process = "client";
	
	@Override
	public void handleIncomingMessage(sf_host host, SFMessage message) {
		// TODO Auto-generated method stub
		if ((message.getType() == sf_type_message.SFP_INFO_REPLY)) {
			InfoReplyMessage info_reply = (InfoReplyMessage) message;
			System.out.println(info_reply);
			
			System.out.println("------------ Flow Stat Request test ------------");
			installTestFlowStatReq(host);
		}
		else if ((message.getType() == sf_type_message.SFP_FLOW_STATE_REPORT)) {
			FlowStatsReplyMessage stats_reply = (FlowStatsReplyMessage) message;
			System.out.println("------------ Flow Stat Report ------------");
			System.out.println(stats_reply);
		}
	}

	@Override
	public void handleOutgoingMessage(sf_host host, SFMessage message) {
		// TODO Auto-generated method stub

	}
	
	private void installTestFlowStatReq(sf_host host) {
		FlowStatsRequestMessage statsReq = new FlowStatsRequestMessage(
       		 new sf_mask(true,true,true, true, true).getMask(), sf_type_operation.SYSFLOW_FILE_READ);
        int pid = 1001;
        
        //statsReq.setSource(sf_type_match.SFP_MATCH_ID, 0, 1001, null);
        statsReq.setSource(sf_type_match.SFP_MATCH_NAME, src_process.length(), 0, src_process.toCharArray());
        
        int inode = 2;
        int uuid = 3;
        //statsReq.setDestination(sf_type_match.SFP_MATCH_ID, 0, uuid, inode, null);
        statsReq.setDestination(sf_type_match.SFP_MATCH_NAME, protected_file.length() , uuid, inode, protected_file.toCharArray());
        
        // temporary mask, opcode for test
        
        System.out.println(statsReq);
		host.sendMsg(statsReq);

	}
}
