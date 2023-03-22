package sysflow_controller.core;

import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.ChannelPromise;
import io.netty.handler.timeout.IdleState;
import io.netty.handler.timeout.IdleStateEvent;
import io.netty.handler.timeout.ReadTimeoutException;

import java.io.IOException;
import java.io.PrintStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.channels.ClosedChannelException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;

import org.jboss.netty.handler.timeout.IdleStateAwareChannelHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import sysflow_controller.core.Controller;
import sysflow_controller.core.SysFlowAgent;
import sysflow_controller.message.EchoReplyMessage;
import sysflow_controller.message.EchoRequestMessage;
import sysflow_controller.message.InfoReplyMessage;
import sysflow_controller.message.InfoRequestMessage;
import sysflow_controller.message.SFMessage;
import sysflow_controller.types.HostID;
import sysflow_controller.types.sf_host;
import sysflow_controller.types.sf_type_message;

public class SFChannelHandler extends ChannelInboundHandlerAdapter {
//public class SFChannelHandler extends IdleStateAwareChannelHandler {
	private static final Logger logger = LoggerFactory
			.getLogger(SFChannelHandler.class);
	private final Controller controller;
	private Channel channel;
	private List<sf_host> hosts;
	private ChannelState state;
	private String channelID;
	private ExecutorService dispatcher;
	
	//map from address to integer-based ID
	static HashMap<SocketAddress, Integer> addrToInt = new HashMap();
	
	// kevin, add echo messages
	private int echoTransactionIds = Integer.MAX_VALUE;
	// kevin, TODO: check xid in use and conflicts with echo xids, e.g., via Set<Long> xid 
	private static int TransactionIds = 1;	// starts from 1, 0 is reserved for handshake

	public SFChannelHandler(Controller controller) {
		this.controller = controller;
		this.state = ChannelState.INIT;
		this.hosts = new ArrayList<sf_host>();
	}
	// kevin, TODO: check xid in use and conflicts with echo xids, e.g., via Set<Long> xid 
	public static int getNewXid() {
		TransactionIds = (TransactionIds + 1) % Integer.MAX_VALUE;
		if(TransactionIds == 0)
			TransactionIds = (TransactionIds + 1) % Integer.MAX_VALUE;
		return TransactionIds;
	}
	
	private void setState(ChannelState state) {
		this.state = state;
	}

	private void illegalMessageReceived(SFMessage ofMessage) {
		logger.warn("Receive illegal message.");
	}

	private void unhandledMessageReceived(SFMessage ofMessage) {
		logger.warn("@@@@@ Receive unhandled message. @@@@@");
		// kevin, debug
		logger.warn("Unhandled Message: " + ofMessage);
	}

	public void channelActive(ChannelHandlerContext ctx) throws Exception {
		this.channel = ctx.channel();
		logger.info("Connection from host {}",
				(Object) this.channel.remoteAddress());
		SocketAddress address = this.channel.remoteAddress();
		this.channelID = address.toString();
		this.dispatcher = Executors.newSingleThreadExecutor();
		this.setState(ChannelState.WAIT_HELLO);
	}

	public void channelInactive(ChannelHandlerContext ctx) throws Exception {
		this.channel = ctx.channel();
		logger.info("host disconnected callback for host {}",
				(Object) this.channel.remoteAddress());
		if (this.dispatcher != null) {
			this.dispatcher.shutdownNow();
			this.dispatcher = null;
		}
		
		super.channelInactive(ctx);	// kevin
	}

	public void channelRead(ChannelHandlerContext ctx, Object msg)
			throws Exception {
		try {
			this.state.processSFMessage(this, (SFMessage) msg);
		} catch (Exception ex) {
			ctx.fireExceptionCaught((Throwable) ex);
		}
	}
	
	@Override
	public void userEventTriggered(final ChannelHandlerContext ctx, final Object evt) {
		SFChannelHandler handler = ctx.pipeline().get(SFChannelHandler.class);
		handler.sendEchoRequest();	// kevin, adds code to handle idle disconnections
	}
	

	public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
		if (cause instanceof ReadTimeoutException) {
			logger.error(
					"Connection closed because of ReadTimeoutException {}",
					(Object) cause.getMessage());
			
		} else {
			if (cause instanceof ClosedChannelException) {
				logger.error("ClosedChannelException occurred");
				return;
			}
			if (cause instanceof RejectedExecutionException) {
				logger.error("Could not process message: queue full");
			} else if (cause instanceof IOException) {
				logger.error("IOException occurred");
			} else {
				cause.printStackTrace();
				logger.error("Error while processing message from {}",
						(Object) cause.getMessage());
			}
		}
		//this.channel.close();
		ctx.channel().close();							// kevin, close a connection through ctx
	}

	private String getHost() {
		return "";
	}

	public Channel getChannel() {
		return this.channel;
	}

	public boolean isEstablished() {
		return this.state.isHandshakeComplete();
	}

	public boolean sendMsg(SFMessage msg) {
		if (this.channel.isActive()) {
			this.channel
					.writeAndFlush((Object) msg, this.channel.voidPromise());
			return true;
		}
		logger.warn(
				"Dropping messages for host {} because channel is not connected: {}",
				(Object) this.getHost(), (Object) msg);
		return false;
	}

	static enum ChannelState {
		INIT(false) {

			@Override
			void processSFMessage(SFChannelHandler handler, SFMessage msg) {
				ChannelState.logProcessOFMessageDetails(handler, msg, this);
			}
		},
		WAIT_HELLO(false) {

			@Override
			void processSFMessage(SFChannelHandler handler, SFMessage msg) {
				ChannelState.logProcessOFMessageDetails(handler, msg, this);
				switch (msg.getType()) {
				case 0: {
					handler.setState(WAIT_INFO_REPLY);
					InfoRequestMessage infoRequest = new InfoRequestMessage(
							msg.getXid());
					handler.channel.writeAndFlush((Object) infoRequest);
					logger.info("received hello message and send out info request message.");
					break;
				}
				default: {
					handler.illegalMessageReceived(msg);
				}
				}
			}
		},
		WAIT_INFO_REPLY(false) {

			@Override
			void processSFMessage(SFChannelHandler handler, SFMessage msg) {
				switch (msg.getType()) {
				case 2: {
					this.processSFInfoReplyMessage(handler,
							(InfoReplyMessage) msg);
					break;
				}
				default: {
					handler.illegalMessageReceived(msg);
				}
				}
			}

			void processSFInfoReplyMessage(SFChannelHandler handler,
					InfoReplyMessage msg) {
				ChannelState.logProcessOFMessageDetails(handler, msg, this);
				Channel channel = handler.getChannel();
				int hash = channel.remoteAddress().hashCode();
				addrToInt.put(channel.remoteAddress(), hash);
				//HostID hid = new HostID(hash);
				
				InetSocketAddress inetSockAddr = (InetSocketAddress) channel.remoteAddress();
				InetAddress inetAddr = inetSockAddr.getAddress();
				String addr = inetAddr.getHostAddress();
				
				HostID hid = new HostID(addr);
				System.out.println(channel.remoteAddress());
				sf_host host = new sf_host(hid);
				SysFlowAgent agent = handler.controller.getSysFlowAgent();
				host.setChannelHandler(handler);
				host.setAgent(agent);
				host.connect();
				handler.setState(ESTABLISHED);
				agent.processMessage(hid, msg);
			}
		},
		ESTABLISHED(true) {

			@Override
			void processSFMessage(SFChannelHandler handler, SFMessage msg) {
				ChannelState.logProcessOFMessageDetails(handler, msg, this);
				Channel channel = handler.getChannel();
				
				InetSocketAddress inetSockAddr = (InetSocketAddress) channel.remoteAddress();
				InetAddress inetAddr = inetSockAddr.getAddress();
				String addr = inetAddr.getHostAddress();
				
				
				HostID hid = new HostID(addr);
				/*
				for (SocketAddress addr : addrToInt.keySet()) {
					if (!channel.remoteAddress().equals(addr))
						continue;
					hid = new HostID(addrToInt.get(addr));
				}
				*/
				switch (msg.getType()) {
				// kevin, use constants
				case sf_type_message.SFP_INFO_REPLY:
				case sf_type_message.SFP_FLOW_STATE_REPORT: {
					SysFlowAgent agent = handler.controller.getSysFlowAgent();
					agent.processMessage(hid, msg);
					break;
				}
				// kevin, add echo messages
				case sf_type_message.SFP_ECHO_REQUEST:
					processEchoRequest(handler, (EchoRequestMessage)msg);
					break;
				case sf_type_message.SFP_ECHO_REPLY:
					// do nothing;
					break;
				// kevin, add action report message
				case sf_type_message.SFP_ACTION_REPORT:
					SysFlowAgent agent = handler.controller.getSysFlowAgent();
					agent.processMessage(hid, msg);
					break;
				default: {
					handler.unhandledMessageReceived(msg);
				}
				}
			}
		};

		private final boolean handshakeComplete;

		abstract void processSFMessage(SFChannelHandler var1, SFMessage var2);

		private static void logProcessOFMessageDetails(
				SFChannelHandler handler, SFMessage msg, ChannelState state) {
			logger.info("Channel State: " + (Object) ((Object) state)
					+ " process SFMessage type: " + msg.getType() + " msg: "
					+ msg.toString());
		}

		private ChannelState(boolean handshakeComplete) {
			this.handshakeComplete = handshakeComplete;
		}

		public boolean isHandshakeComplete() {
			return this.handshakeComplete;
		}
		
		void processEchoRequest(SFChannelHandler handler, EchoRequestMessage msg){
			sendEchoReply(handler, msg);
			
			
		}
		/*
		void processEchoReply(EchoReplyMessage msg) {
			// do nothing
		}
		*/
	}
	
	// kevin, add echo messages
	private void sendEchoRequest() {
		echoTransactionIds = (echoTransactionIds - 1) % Integer.MAX_VALUE;
		if (echoTransactionIds == 0) // 0 is reserved for handshake
			echoTransactionIds = (echoTransactionIds - 1) % Integer.MAX_VALUE;
		
		EchoRequestMessage echoRequest = new EchoRequestMessage(echoTransactionIds);
		this.channel.writeAndFlush((Object) echoRequest);
		logger.info("Echo Request message is being sent...");
	}
	// kevin, add echo messages
	static private void sendEchoReply(SFChannelHandler handler, EchoRequestMessage msg) {
		
		EchoReplyMessage echoReply = new EchoReplyMessage(msg.getXid());
		handler.channel.writeAndFlush((Object) echoReply);
		logger.info("Echo Reply message is being sent...");
	}

}