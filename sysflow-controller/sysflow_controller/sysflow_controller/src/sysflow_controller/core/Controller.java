package sysflow_controller.core;

import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.Channel;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.epoll.EpollServerSocketChannel;
import io.netty.channel.group.ChannelGroup;
import io.netty.channel.group.DefaultChannelGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.util.concurrent.GlobalEventExecutor;

import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.util.Iterator;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Representation of a SysFlow controller.
 */

public class Controller {

	private static final Logger log = LoggerFactory.getLogger(Controller.class);

	protected int sysFlowPort = 5001;

	private ChannelGroup cg;

	private SysFlowAgent agent;
	
	// system start time
	protected long startTime;

	// **************
	// Initialization
	// **************

	/**
	 * Initialize internal data structure
	 */
	public void init() {
		this.startTime = System.currentTimeMillis();
		cg = new DefaultChannelGroup(GlobalEventExecutor.INSTANCE);
	}

	private void run(int port) {
		EventLoopGroup group = new NioEventLoopGroup();
		final ServerBootstrap bootstrap = new ServerBootstrap();
		bootstrap.group(group);
		bootstrap.channel(NioServerSocketChannel.class);
		bootstrap.localAddress(new InetSocketAddress("localhost", port));

		bootstrap.childHandler(new SFChannelInitializer(this, null));

		// add the channel into channel group
		cg.add(bootstrap.bind(port).syncUninterruptibly().channel());
		log.info("Listening for OF switch connections on {}", port);
	}

	private void terminate() {
		if (cg == null) {
			return;
		}
		Iterator<Channel> itr = cg.iterator();

		while (itr.hasNext()) {
			Channel c = itr.next();
			SocketAddress addr = c.localAddress();
			InetSocketAddress inetAddr = (InetSocketAddress) addr;
			Integer port = inetAddr.getPort();
			log.info("No longer listening for OF switch connections on {}",
					port);
			c.close();
			itr.remove();
		}
	}

	/**
	 * Starts the Sysflow controller.
	 */
	public void start(SysFlowAgent ag) {
		log.info("Start sysflow controller IO");

		this.agent = ag;
		this.init();
		this.run(this.sysFlowPort);
	}

	/**
	 * Stops the Sysflow controller.
	 */
	public void stop() {
		log.info("Stop sysflow controller IO");
		
		this.terminate();
		cg.close();
	}
	
	public SysFlowAgent getSysFlowAgent(){
		return this.agent;
	}

}
