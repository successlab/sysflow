package sysflow_controller.types;

import java.util.List;

import sysflow_controller.core.SFChannelHandler;
import sysflow_controller.core.SysFlowAgent;
import sysflow_controller.message.SFMessage;

/**
 * class for SysFlow host (DataPlane) profile
 * 
 * @author ray
 *
 */

public class sf_host {
	private HostID hostID;
	private SFChannelHandler handler;
	private SysFlowAgent agent;

	public sf_host(HostID hid) {
		this.hostID = hid;
		this.handler = null;
	}

	public sf_host(HostID hid, SFChannelHandler h) {
		this.hostID = hid;
		this.handler = h;
	}

	public void setAgent(SysFlowAgent ag) {
		this.agent = ag;
	}

	public HostID getHostID() {
		return this.hostID;
	}

	public void setChannelHandler(SFChannelHandler h) {
		this.handler = h;
	}

	public SFChannelHandler getChannelHandler() {
		return this.handler;
	}

	public boolean isEstablished() {
		return this.handler.isEstablished();
	}

	public void sendMsg(List<SFMessage> msgs) {
		for (SFMessage msg : msgs) {
			this.handler.sendMsg(msg);
		}
	}

	public void sendMsg(SFMessage msg) {
		this.handler.sendMsg(msg);
	}

	public void connect() {
		this.agent.addConnectedHost(this.hostID, this);
	}
}
