package sysflow_controller.apps;

import java.io.PrintStream;

import sysflow_controller.core.SysFlowMessageListener;
import sysflow_controller.message.FlowModMessage;
import sysflow_controller.message.SFMessage;
import sysflow_controller.types.HostID;
import sysflow_controller.types.sf_action;
import sysflow_controller.types.sf_host;
import sysflow_controller.types.sf_mask;
import sysflow_controller.types.sf_type_operation;

public class test_flow_mod implements SysFlowMessageListener {

	@Override
	public void handleIncomingMessage(sf_host host, SFMessage message) {
		if ((message.getType() == 2) || (message.getType() == 5)) {
			System.out.println("enter test flow mod program");
			installTestFlowMod(host);
		}
	}

	@Override
	public void handleOutgoingMessage(sf_host host, SFMessage message) {
	}

	private void installTestFlowMod(sf_host host) {
		FlowModMessage flowMod = new FlowModMessage(FlowModMessage.SFPFM_ADD, 1, new sf_mask(true, true,
				true, true, true).getMask(), sf_type_operation.SYSFLOW_FILE_READ);
		int pid = 1001;
		flowMod.setSource(0, 0, 1001, null);
		int inode = 2;
		int uuid = 3;
		flowMod.setDestination(0, 0, uuid, inode, null);
		flowMod.addAction(new sf_action(sf_action.SYSFLOW_ACTION_DENY, null, 0));

		System.out.println("send test flow mod message");
		host.sendMsg(flowMod);
	}
}
