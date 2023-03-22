package sysflow_controller.core;

import sysflow_controller.message.SFMessage;
import sysflow_controller.types.HostID;
import sysflow_controller.types.sf_host;

public interface SysFlowAgent {
	 
    /**
     * add connected host to the agent
     * @param hid
     * @param host
     * @return
     */
    public boolean addConnectedHost(HostID hid, sf_host host);
    
    /**
     * dispatch incoming sysflow messages to handlers
     * @param hid
     * @param m
     */
    public void processMessage(HostID hid, SFMessage m);
    
    /**
     * dispaptch outging sysflow messages to handlers
     * @param hid
     * @param msg
     */
    public void processOutGoingMessage(HostID hid, SFMessage msg);
}
