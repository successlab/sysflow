package sysflow_controller.core;


import java.util.logging.Logger;

import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelPipeline;
import io.netty.channel.socket.SocketChannel;
import io.netty.handler.ssl.SslHandler;
import io.netty.handler.timeout.IdleStateHandler;
import io.netty.handler.timeout.ReadTimeoutHandler;
import io.netty.util.concurrent.EventExecutorGroup;

/**
 * Creates a ChannelInitializer for a server-side openflow channel.
 */
public class SFChannelInitializer
    extends ChannelInitializer<SocketChannel> {

	private final Logger logger = Logger.getLogger("SFChannelInitializer");


   // private final SSLContext sslContext;
    protected Controller controller;
    protected EventExecutorGroup pipelineExecutor;

    public SFChannelInitializer(Controller controller,
                                   EventExecutorGroup pipelineExecutor) {
        super();
        this.controller = controller;
        this.pipelineExecutor = pipelineExecutor;
      //  this.sslContext = sslContext;
    }

    @Override
    protected void initChannel(SocketChannel ch) throws Exception {

        SFChannelHandler handler = new SFChannelHandler(controller);

        ChannelPipeline pipeline = ch.pipeline();
     
        pipeline.addLast("sfmsgencoder", SFMessageEncoder.getInstance());
        pipeline.addLast("sfmsgdecoder", SFMessageDecoder.getInstance());

        pipeline.addLast("idle", new IdleStateHandler(25, 25, 0));			// kevin, set reader timeout same write timeout
        pipeline.addLast("timeout", new ReadTimeoutHandler(30));

      
     //   pipeline.addLast("handshaketimeout",
     //                    new HandshakeTimeoutHandler(handler, 60));
        // ExecutionHandler equivalent now part of Netty core
        if (pipelineExecutor != null) {
            pipeline.addLast(pipelineExecutor, "handler", handler);
        } else {
            pipeline.addLast("handler", handler);
        }
    }
}