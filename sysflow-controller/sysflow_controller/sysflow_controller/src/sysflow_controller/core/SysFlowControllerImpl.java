package sysflow_controller.core;

import java.io.IOException;
import java.io.PrintStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.SocketChannel;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.CopyOnWriteArraySet;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import sysflow_controller.apps.chacl;
import sysflow_controller.apps.cldlp;
import sysflow_controller.apps.file_reflector;
import sysflow_controller.apps.test_flow_stat_req;
import sysflow_controller.message.FlowModMessage;
import sysflow_controller.message.FlowStatsRequestMessage;
import sysflow_controller.message.HelloMessage;
import sysflow_controller.message.InfoReplyMessage;
import sysflow_controller.message.InfoRequestMessage;
import sysflow_controller.message.SFMessage;
import sysflow_controller.types.HostID;
import sysflow_controller.types.sf_action;
import sysflow_controller.types.sf_host;
import sysflow_controller.types.sf_mask;
import sysflow_controller.types.sf_type_operation;

public class SysFlowControllerImpl implements SysFlowController {
	private static final int SERVER_PORT = 5001;
	private static final int SOCKET_BUFFER = 2000;
	private static final Logger logger = LoggerFactory
			.getLogger(SysFlowControllerImpl.class);

	protected static final Set<SysFlowMessageListener> sfMessageListener = new CopyOnWriteArraySet();

	public static ConcurrentMap<HostID, sf_host> connectedHosts = new ConcurrentHashMap();

	private static final Controller ctrl = new Controller();

	protected static SysFlowAgent agent = new SysFlowDataPlaneAgent();
	private static HostState hostState;

	public SysFlowControllerImpl() {
	}

	public static enum HostState {
		INIT, STARTUP, COMPLETE;
	}

	public static void main(String[] args) {
		//sfMessageListener.add(new test_flow_mod());
		
//		sfMessageListener.add(new file_reflector());
		
//		sfMessageListener.add(new test_flow_stat_req());
		
//		sfMessageListener.add(new chacl());

		sfMessageListener.add(new cldlp());
		
		
		ctrl.start(agent);
	}

	private static void installMessage(SocketChannel socket, SFMessage outMsg)
			throws IOException {
		SFMessage.sendMessage(socket, outMsg);
	}

	private static void handleMessage(SocketChannel socket, SFMessage inMsg)
			throws IOException {
		if (inMsg == null) {
			throw new IOException("Parsing null SysFlow message. ");
		}

		SFMessage outMsg = null;

		if ((inMsg instanceof HelloMessage)) {
			outMsg = new InfoRequestMessage(inMsg.getXid());

			logger.info("Length of sendout msg: " + outMsg.getLength());

			SFMessage.sendMessage(socket, outMsg);
			logger.info("send out Host Information Request message.");
		} else if (!(inMsg instanceof InfoReplyMessage)) {

			logger.warn("Unexpected incoming message " + inMsg);
		}
	}

	private static SFMessage getMessage(SocketChannel socket)
			throws IOException {
		ByteBuffer dataBuffer = ByteBuffer.allocate(2048);

		//dataBuffer.order(ByteOrder.LITTLE_ENDIAN);

		logger.info("Socket opened to " + socket.getRemoteAddress());

		SFMessage msg = SFMessage.getMessageFromSocket(socket, dataBuffer);

		return msg;
	}

	static class SysFlowDataPlaneAgent implements SysFlowAgent {
		private final Logger log = LoggerFactory
				.getLogger(SysFlowDataPlaneAgent.class);
		static SysFlowDataPlaneAgent agent;

		protected SysFlowDataPlaneAgent() {
			agent = this;
		}

		protected static SysFlowDataPlaneAgent getInstance() {
			return agent;
		}

		public boolean addConnectedHost(HostID hid, sf_host host) {
			if (SysFlowControllerImpl.connectedHosts.get(hid) != null) {
				log.error(
						"Trying to add connectedSwitch but found a previous value for dpid: {}",
						hid);
				return false;
			}
			log.info("Added Host {}", hid);
			SysFlowControllerImpl.connectedHosts.put(hid, host);

			return true;
		}

		public void processMessage(HostID hid, SFMessage m) {
			System.out.println("dispatching sysflow messages to apps.");

			sf_host host = (sf_host) SysFlowControllerImpl.connectedHosts
					.get(hid);

			for (HostID h : SysFlowControllerImpl.connectedHosts.keySet()) {
				if (host == null) {
					host = (sf_host) SysFlowControllerImpl.connectedHosts
							.get(h);
				}
			}
			for (HostID h : SysFlowControllerImpl.connectedHosts.keySet()) {
				System.out.println(h);
			}

			for (SysFlowMessageListener listener : SysFlowControllerImpl.sfMessageListener) {
				if (listener != null) {
					listener.handleIncomingMessage(host, m);
				}
			}
		}

		public void processOutGoingMessage(HostID hid, SFMessage msg) {
			sf_host host = (sf_host) SysFlowControllerImpl.connectedHosts
					.get(hid);
			for (SysFlowMessageListener listener : SysFlowControllerImpl.sfMessageListener) {
				listener.handleOutgoingMessage(host, msg);
			}
		}
	}

	public Iterable<sf_host> getHosts() {
		return connectedHosts.values();
	}

	public sf_host getHost(HostID hid) {
		return (sf_host) connectedHosts.get(hid);
	}

	public void addMessageListener(SysFlowMessageListener listener) {
		sfMessageListener.add(listener);
	}

	public void removeMessageListener(SysFlowMessageListener listener) {
		sfMessageListener.remove(listener);
	}

	public void write(HostID hid, SFMessage message) {
		sf_host host = (sf_host) connectedHosts.get(hid);

		if (host == null) {
			logger.warn(
					"Cannot send out message {} due to the host {} is not connected.",
					message, hid);
			return;
		}

		host.sendMsg(message);
	}

	private static void testInstallHello(SocketChannel socket) {
		HelloMessage helloMsg = new HelloMessage(101);

		System.out.println(helloMsg.toString());
		try {
			installMessage(socket, helloMsg);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	private static void testInstallInfoRequest(SocketChannel socket) {
		InfoRequestMessage infoRequest = new InfoRequestMessage(22);

		System.out.println(infoRequest.toString());
		try {
			installMessage(socket, infoRequest);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	private static void testInstallFlowMod(SocketChannel socket) {
		FlowModMessage flowMod = new FlowModMessage(0, 1,
       		 new sf_mask(true,true,true, false, false).getMask(), sf_type_operation.SYSFLOW_FILE_READ);
		int pid = 1001;
		flowMod.setSource(0, 0, 1001, null);
		int inode = 2;
		int uuid = 3;
		flowMod.setDestination(0, 0, uuid, inode, null);
		flowMod.addAction(new sf_action(2, null, 0));
		try {
			installMessage(socket, flowMod);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	private static void testInstallFlowStatsRequest(SocketChannel socket) {
		FlowStatsRequestMessage statsReq = new FlowStatsRequestMessage(
				new sf_mask(true, true, true, false, false).getMask(), 1);
		int pid = 1001;
		statsReq.setSource(0, 0, 1001, null);
		int inode = 2;
		int uuid = 3;
		statsReq.setDestination(0, 0, uuid, inode, null);
		try {
			installMessage(socket, statsReq);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
}