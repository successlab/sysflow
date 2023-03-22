package sysflow_controller.apps;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import sysflow_controller.core.SysFlowMessageListener;
import sysflow_controller.message.ActionReportMessage;
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

public class cldlp implements SysFlowMessageListener {

	// the host stores user sensitive files
	String data_host = "192.168.150.1";

	// record ids or processes in each host that access the sensitive file
	// Map<String, Integer> monitored_pid = new HashMap<>();

	// tag for sensitive information flow
	int tag = 101;

	String sensitive_file = "/tmp/monitored/w2";

	@Override
	public void handleIncomingMessage(sf_host host, SFMessage message) {
		if ((message.getType() == sf_type_message.SFP_INFO_REPLY)) {

			System.out.println("Received INFO_REPLY from host " + host.getHostID());
			installMonitorFlowRule(host, host.getHostID().getHostID().equals(data_host));
		}

		if ((message.getType() == sf_type_message.SFP_ACTION_REPORT)) {
			if(host.getHostID().getHostID().equals(data_host)){
				ActionReportMessage msg = (ActionReportMessage) message;

				// get pid of the event
				String file_path;
				Integer pid, mask;

				Pattern p = Pattern.compile("Process (\\d+) is trying to access file (.+) with mask (\\d+)");
				Matcher m = p.matcher(msg.getData());
				if(m.find()){
					pid = Integer.parseInt(m.group(1));
					file_path = m.group(2);
					mask = Integer.parseInt(m.group(3));

					installTrackFlowRule(host, pid);
				}

			}
		}
	}

	@Override
	public void handleOutgoingMessage(sf_host host, SFMessage message) {
	}

	private void installMonitorFlowRule(sf_host host, boolean isDataHost) {
		FlowModMessage flowMod;
		int pid = 1001;

		if (isDataHost) {
			flowMod = new FlowModMessage(FlowModMessage.SFPFM_ADD, 1, new sf_mask(false, true,
					true, false, true).getMask(), sf_type_operation.SYSFLOW_FILE_READ);

			flowMod.setSource(sf_type_match.SFP_MATCH_ID, 0, pid, null);

			System.out.println("sending monitor flow rule message to data host");
			int inode = 0;
			int uuid = 0;
			flowMod.setDestination(sf_type_match.SFP_MATCH_NAME, sensitive_file.length(), uuid,
					inode, sensitive_file.toCharArray());
			flowMod.addAction(new sf_action(sf_action.SYSFLOW_ACTION_REPORT,
					null, 0));
		}
		else{
			flowMod = new FlowModMessage(FlowModMessage.SFPFM_ADD, 1, new sf_mask(false, true,
					true, false, false).getMask(), sf_type_operation.SYSFLOW_FILE_READ);
			System.out.println("sending monitor flow rule message to normal host");

			flowMod.setSource(sf_type_match.SFP_MATCH_ID, 0, pid, null);

			int inode = 0;
			int uuid = 0;
			flowMod.setDestination(sf_type_match.SFP_MATCH_SOCKET, 0, uuid,
					inode, null);
			flowMod.addAction(new sf_action(sf_action.SYSFLOW_ACTION_DECODE,
					ByteBuffer.allocate(4).putInt(tag).array(), 4));
			flowMod.addAction(new sf_action(sf_action.SYSFLOW_ACTION_REPORT,
					null, 0));
		}

		host.sendMsg(flowMod);
	}

	private void installTrackFlowRule(sf_host host, int pid) {
		FlowModMessage flowMod = new FlowModMessage(FlowModMessage.SFPFM_ADD, 1, new sf_mask(true, true,
				true, true, false).getMask(), sf_type_operation.SYSFLOW_SOCKET_WRITE);

		flowMod.setSource(sf_type_match.SFP_MATCH_ID, 0, pid, null);

		int inode = 0;
		int uuid = 0;

		String dst_ip = "192.168.150.1";

//		flowMod.setDestination(sf_type_match.SFP_MATCH_SOCKET, dst_ip.length(), uuid, inode, dst_ip.toCharArray());
		flowMod.setDestination(sf_type_match.SFP_MATCH_SOCKET, 0, uuid, inode, null);
		flowMod.addAction(new sf_action(sf_action.SYSFLOW_ACTION_ENCODE,
				ByteBuffer.allocate(4).putInt(tag).array(), 4));

		System.out.println("send redirection flow mod message");

		host.sendMsg(flowMod);
	}

}
