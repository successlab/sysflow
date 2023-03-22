package sysflow_controller.core;

import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import sysflow_controller.message.SFMessage;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelPromise;
import io.netty.channel.ChannelOutboundHandlerAdapter;
import io.netty.handler.codec.EncoderException;

// kevin, CAREFUL! 
// 			After disconnection from the host, the second connection from the client raised an exception as follows:
// 			io.netty.channel.ChannelPipelineException:is not a @Sharable handler, so can't be added or removed multiple times.
//			I'm not sure this is proper solution.
@SFChannelHandler.Sharable
public class SFMessageEncoder extends ChannelOutboundHandlerAdapter{

	private static final Logger logger = LoggerFactory.getLogger(SFMessageEncoder.class);

    private static final SFMessageEncoder INSTANCE = new SFMessageEncoder();

    public static SFMessageEncoder getInstance() {
        return INSTANCE;
    }

    private SFMessageEncoder() {}

    protected final void encode(ChannelHandlerContext ctx,
                          SFMessage msg,
                          ByteBuf out) throws IOException {
    	// kevin
    	//logger.info(msg.toString());
		msg.writeTo(out);
 
    }

    // MessageToByteEncoder without dependency to TypeParameterMatcher
    @Override
    public void write(ChannelHandlerContext ctx,
                      Object msg,
                      ChannelPromise promise) {

        ByteBuf buf = null;
        try {
            if (msg instanceof Iterable) {
                @SuppressWarnings("unchecked")
                Iterable<SFMessage> sfmsgs =  (Iterable<SFMessage>) msg;
                buf = ctx.alloc().ioBuffer();

               // encode(ctx, sfmsgs, buf);

                if (buf.isReadable()) {
                	logger.info("SysFlow Message Encoder: Iterable SFMessages");
                    ctx.write(buf, promise);
                } else {
                	//logger.warn("NOTHING WAS WRITTEN for {}", msg);
                	logger.info("Nothing was written to message");
                    buf.release();
                    ctx.write(Unpooled.EMPTY_BUFFER, promise);
                }
                buf = null;
                	
            } else {
            	logger.info("SysFlow Message Encoder: single message: {}", msg);
            	
            	SFMessage sfmsg = (SFMessage) msg;
            	 buf = ctx.alloc().ioBuffer();
            	 encode(ctx, sfmsg, buf);
            	 
            	 if (buf.isReadable()) {
                     ctx.write(buf, promise);
                 } else {
                 	//logger.warn("NOTHING WAS WRITTEN for {}", msg);
                 	logger.info("NOthing was written to message");
                     buf.release();
                     ctx.write(Unpooled.EMPTY_BUFFER, promise);
                 }
            	 buf = null;
            	 
            }
        } catch (EncoderException e) {
        	//logger.error("EncoderException handling {}", msg, e);
        	logger.info("EncoderException handling");
        	throw e;
        } catch (Throwable e) {
        	//logger.error("Exception handling {}", msg, e);
        	logger.info("Exception handling");
            throw new EncoderException(e);
        } finally {
            if (buf != null) {
                buf.release();
            }
        }
    }

}