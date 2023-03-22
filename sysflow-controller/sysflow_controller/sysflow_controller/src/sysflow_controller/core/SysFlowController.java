package sysflow_controller.core;

import sysflow_controller.message.SFMessage;
import sysflow_controller.types.HostID;
import sysflow_controller.types.sf_host;

public interface SysFlowController {
	
	/**
	 * return all SF-enabled hosts known to the controller
	 * @return Iterable of SF hosts
	 */
	 Iterable<sf_host> getHosts();
	 
	 /**
	  * return the SF host given the id
	  * @param id the id of the SF-enabled host
	  * @return the interface to the SF-enabled host
	  */
	 sf_host getHost(HostID id);
	 
	 /**
	  * add sysflow message listener to the message loop
	  * @param listener
	  */
	 void addMessageListener(SysFlowMessageListener listener);
	 
	 /**
	  * remove sysflow message listener from the message loop
	  * @param listener
	  */
	 void removeMessageListener(SysFlowMessageListener listener);
	 
	 /**
	  * send a message to a particular SF-enabled host
	  * @param host_id
	  * @param message
	  */
	 void write(HostID host_id, SFMessage message);
	 
}
