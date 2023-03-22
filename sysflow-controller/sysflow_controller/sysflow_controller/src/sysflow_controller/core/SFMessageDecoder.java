package sysflow_controller.core;

import java.io.IOException;
import java.util.Collections;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import sysflow_controller.message.SFMessage;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelPromise;
import io.netty.channel.ChannelOutboundHandlerAdapter;
import io.netty.handler.codec.ByteToMessageDecoder;
import io.netty.handler.codec.EncoderException;

public final class SFMessageDecoder extends ByteToMessageDecoder {

	private static final Logger log = LoggerFactory.getLogger(SFMessageDecoder.class);

	final static int MINIMUM_LENGTH = 12;

	public static SFMessageDecoder getInstance() {
		// not Sharable
		return new SFMessageDecoder();
	}

	private SFMessageDecoder() {
	}

	@Override
	protected void decode(ChannelHandlerContext ctx, ByteBuf byteBuf,
			List<Object> out) throws Exception {

		if (!ctx.channel().isActive() && byteBuf.readableBytes() < MINIMUM_LENGTH) {
			log.debug("[ERROR] readable bytes of buffer is less than " + MINIMUM_LENGTH);
			return;
		}
		
		log.debug("********** decode(): buffer length: " + byteBuf.readableBytes());

		SFMessage message = SFMessage.readFrom(byteBuf);
		out.add(message);
	}

}