package sysflow_controller.core;

import sysflow_controller.message.SFMessage;
import sysflow_controller.types.HostID;
import sysflow_controller.types.sf_host;


/*
 * Notifies handlers about all SysFlow messages
 */
public interface SysFlowMessageListener {

	/**
	 * handle all incoming SysFlow messages
	 * @param hid the host generated message
	 * @param message the incoming SysFlow message
	 */
	void handleIncomingMessage(sf_host  host, SFMessage message);
	
	/**
	 * handle all outgoing SysFlow messages
	 * @param hid the host where the message be sent
	 * @param message the outgoing SysFlow message
	 */
	void handleOutgoingMessage(sf_host  host, SFMessage message);

}
