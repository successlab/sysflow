package sysflow_controller.message;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.SocketChannel;
import java.util.logging.Logger;

import io.netty.buffer.ByteBuf;

class SFMessageType {
	public static final int SFP_HELLO = 0;
	public static final int SFP_INFO_REQUEST = 1;
	public static final int SFP_INFO_REPLY = 2;
	public static final int SFP_FLOW_MOD = 3;
	public static final int SFP_FLOW_STATE_REQUEST = 4;
	public static final int SFP_FLOW_STATE_REPORT = 5;
	public static final int SFP_ECHO_REQUEST = 6;		// kevin, add ECHO messages to avoid idle disconnection
	public static final int SFP_ECHO_REPLY = 7;			// kevin, add ECHO messages to avoid idle disconnection
	public static final int SFP_ACTION_REPORT = 8;		// kevin, add ACTION_REPORT message
}

/**
 * Message is the base class of all messages to be send or received over the
 * socket. In this class we present the full set of functions needed to send and
 * receive data over a socket. In a real world case, we'd probably want better
 * separation of concerns but this is more than satisfactory for an example.
 *
 * Message has two abstract methods that must be implemented, these two methods
 * handle conversion to and from a byte buffer.
 */
public abstract class SFMessage {
	protected int len;
	protected int type;
	protected int xid;

	private final static Logger LOGGER = Logger.getLogger("MESSAGE");

	/**
	 * Must be implemented by all sub classes to convert the bytes in the buffer
	 * into the fields in this message object.
	 * 
	 * @param buffer
	 *            the byte buffer containing the message
	 */
	public abstract void fromBytes(ByteBuffer buffer);

	public abstract void fromBytes(ByteBuf buffer);

	/**
	 * Must be implemented by all sub classes to compute the length of the
	 * message
	 * 
	 * @return the length of the message
	 */
	public abstract int length();

	/**
	 * Must be implemented by all sub classes to convert the message into bytes
	 * in the buffer.
	 * 
	 * @param buffer
	 *            the byte buffer to receive the message data.
	 * @throws IOException
	 */
	public abstract void toBytes(ByteBuffer buffer) throws IOException;

	/**
	 * We use the simple class name (without package) as the message type. This
	 * is not entirely efficient, but will suffice for this example.
	 * 
	 * @return the message type.
	 */
	private int messageType() {
		return this.type;
	}

	/**
	 * Converts a string into a message field in the buffer passed in. into the
	 * buffer
	 * 
	 * @param buffer
	 *            the buffer that represents the socket
	 * @param str
	 *            the string to be written
	 */
	public static void stringToMsg(ByteBuffer buffer, String str) {
		byte[] bytes = str.getBytes();
		int len = bytes.length;
		buffer.putShort((short) len);
		buffer.put(bytes);
	}

	/**
	 * Converts a byte array into a message field in the buffer passed in. into
	 * the buffer
	 * 
	 * @param buffer
	 *            the buffer that represents the socket
	 * @param bytes
	 *            the byte array of the message
	 */
	public static void bytesToMsg(ByteBuffer buffer, byte[] bytes) {
		int len = bytes.length;
		// buffer.putShort((int) len);
		buffer.put(bytes);
	}

	/**
	 * converts a message field from the buffer into a string
	 * 
	 * @param buffer
	 *            the message as a buffer
	 * @return the string field
	 */
	public static String stringFromMsg(ByteBuffer buffer) {
		int len = buffer.getInt();
		byte[] bytes = new byte[len];
		buffer.get(bytes);
		return new String(bytes);
	}

	/**
	 * @param buffer
	 *            the message a a buffer
	 * @return the length of the message
	 */
	public static int lenFromMsg(ByteBuffer buffer) {
		int len = buffer.getInt(0);
		return len;
	}

	public static int lenFromMsg(ByteBuf buffer) {
		int len = buffer.getInt(0);
		return len;
	}

	/**
	 * @param buffer
	 *            the message a a buffer
	 * @return the type of the message
	 */
	public static int typeFromMsg(ByteBuffer buffer) {
		int type = buffer.getInt(4);
		return type;
	}

	public static int typeFromMsg(ByteBuf buffer) {
		int type = buffer.getInt(4);
		return type;
	}

	/**
	 * @param buffer
	 *            the message a a buffer
	 * @return the transmission id of the message
	 */
	public static int xidFromMsg(ByteBuffer buffer) {
		int xid = buffer.getInt(8);
		return xid;
	}

	public static int xidFromMsg(ByteBuf buffer) {
		int xid = buffer.getInt(8);
		return xid;
	}

	/**
	 * Reads a single message from the socket, returning it as a sub class of
	 * Message
	 * 
	 * @param socket
	 *            socket to read from
	 * @param dataBuffer
	 *            the data buffer to use
	 * @return a message if it could be parsed
	 * @throws IOException
	 *             if the message could not be converted.
	 */
	public static SFMessage getMessageFromSocket(SocketChannel socket,
			ByteBuffer dataBuffer) throws IOException {

		// read the first 4 bytes to get the message length.
		readMessage(socket, dataBuffer, dataBuffer.limit());

		int len = lenFromMsg(dataBuffer);

		// TODO: check the len of the packet is valid or not
		// check(dataBuffer, len);

		int type = typeFromMsg(dataBuffer);

		LOGGER.warning("[readFrom:getMessageFromSocket]Receiving message len: " + len + " type: " + type);

		SFMessage msg = null;

		switch (type) {
		case SFMessageType.SFP_HELLO:
			msg = new HelloMessage();
			break;
		case SFMessageType.SFP_INFO_REPLY:
			msg = new InfoReplyMessage();
			break;
		case SFMessageType.SFP_FLOW_STATE_REPORT:
			msg = new FlowStatsReplyMessage();
			break;
		case SFMessageType.SFP_ECHO_REQUEST:
			msg = new EchoRequestMessage();
			break;
		case SFMessageType.SFP_ECHO_REPLY:
			msg = new EchoReplyMessage();
			break;
		// kevin, add action report message
		case SFMessageType.SFP_ACTION_REPORT:
			msg = new ActionReportMessage();
			break;
		default:
			LOGGER.warning("Unknown message type.");
		}

		// if we couldn't convert the message, raise an exception
		if (msg == null) {
			throw new IOException("Unknown message type: " + type);
		}

		msg.fromBytes(dataBuffer);

		return msg;

	}

	public void writeTo(ByteBuf buffer) throws IOException {
		buffer.writeBytes(this.serialize());
	}

	/**
	 * Send any message derived from Message base class on the socket,
	 * 
	 * @param channel
	 *            the channel on which the message is sent
	 * @param toSend
	 *            the message to send.
	 * @throws IOException
	 *             if there is a problem during writing.
	 */
	public static void sendMessage(SocketChannel channel, SFMessage toSend)
			throws IOException {

		// we need to put the message type into the buffer first.
		ByteBuffer bbMsg = ByteBuffer.allocate(2048);

		byte[] bytes = toSend.serialize();
		bytesToMsg(bbMsg, bytes);
		bbMsg.flip();

		long written = channel.write(new ByteBuffer[] { bbMsg });

		LOGGER.info("Message written to socket: " + toSend
				+ " total length was: " + written);
	}

	/**
	 * trick to convert ByteBuf to ByteBuffer TODO refactor relevant functions
	 * to handle ByteBuf directly
	 * 
	 * @param buffer
	 * @return
	 */

	private static ByteBuffer toNioBuffer(ByteBuf buffer) {
		if (buffer.isDirect()) {
			return buffer.nioBuffer();
		}

		final byte[] bytes = new byte[buffer.readableBytes()];
		buffer.getBytes(buffer.readerIndex(), bytes);
		return ByteBuffer.wrap(bytes);
	}

	/**
	 * read SFMessage from ByteBuf, used for SFMessageDecoder
	 * 
	 * @param buffer
	 * @return
	 * @throws IOException
	 */
	public static SFMessage readFrom(ByteBuf buffer) throws IOException {
		int start = buffer.readerIndex();

		int maxLen = buffer.readableBytes();

		ByteBuffer dataBuffer = toNioBuffer(buffer);

		// convert to little endian order
		//dataBuffer.order(ByteOrder.LITTLE_ENDIAN);

		int len = lenFromMsg(dataBuffer);
		
		LOGGER.info("[readFrom:ByteBuf] Receiving message len: " + len + ", maxLen: " + maxLen);

		// kevin, FIXME: comment out until client fixes header.length properly
		/*
		if (len > maxLen) {
			return null;
		}
		*/

		// TODO: check the len of the packet is valid or not
		// check(dataBuffer, len);

		int type = typeFromMsg(dataBuffer);

		LOGGER.info("[readFrom:ByteBuf] Receiving message type: " + type);

		SFMessage msg = null;

		switch (type) {
		case SFMessageType.SFP_HELLO:
			msg = new HelloMessage();
			break;
		case SFMessageType.SFP_INFO_REPLY:
			msg = new InfoReplyMessage();
			break;
		case SFMessageType.SFP_FLOW_STATE_REPORT:
			msg = new FlowStatsReplyMessage();
			break;
		case SFMessageType.SFP_ECHO_REQUEST:
			msg = new EchoRequestMessage();
			break;
		case SFMessageType.SFP_ECHO_REPLY:
			msg = new EchoReplyMessage();
			break;
		// kevin, add action report message
		case SFMessageType.SFP_ACTION_REPORT:
			msg = new ActionReportMessage();
			break;
		default:
			LOGGER.warning("Unknown message type.");
		}

		// if we couldn't convert the message, raise an exception
		if (msg == null) {
			throw new IOException("Unknown message type: " + type);
		}

		msg.fromBytes(dataBuffer);
		
		// kevin, print a received message
		LOGGER.info("Message received: \n" + msg);

		// buffer.readerIndex(start + len);
		buffer.clear();
		return msg;

	}

	/**
	 * When we are reading messages from the wire, we need to ensure there are
	 * enough bytes in the buffer to fully decode the message. If not we keep
	 * reading until we have enough.
	 * 
	 * @param socket
	 *            the socket to read from
	 * @param buffer
	 *            the buffer to store the bytes
	 * @param required
	 *            the amount of data required.
	 * @throws IOException
	 *             if the socket closes or errors out.
	 */
	private static void readMessage(SocketChannel socket, ByteBuffer buffer,
			int required) throws IOException {
		// if there's already something in the buffer, then compact it and
		// prepare it for writing again.
		if (buffer.position() != 0) {
			buffer.compact();
		}

		// indicate if the first part of bytes read from socket
		boolean first = true;
		;

		// we loop until we have enough data to decode the message
		while (first || buffer.position() < lenFromMsg(buffer)) {

			first = false;

			// try and read, if read returns 0 or less, the socket's closed.
			int len = socket.read(buffer);
			if (!socket.isOpen() || len <= 0) {
				throw new IOException("Socket closed while reading");
			}

			LOGGER.info("Bytes now in buffer: " + buffer.remaining()
					+ " read from socket: " + len);
		}

		// and finally, prepare the buffer for reading.
		buffer.flip();
	}

	/**
	 * retrieve the type id of the message
	 * 
	 * @return the type of the message
	 */
	public int getType() {
		return this.type;
	}

	/**
	 * retrieve the length id of the message
	 * 
	 * @return the length of the message
	 */
	public int getLength() {
		return this.len;
	}

	/**
	 * retrieve the transmission id of the message
	 * 
	 * @return the xid of the message
	 */
	public int getXid() {
		return this.xid;
	}

	/**
	 * convert integer to byte array for serialization
	 * 
	 * @param value
	 *            the value of integer
	 * @return the byte array of the input integer
	 */
	protected static final byte[] intToByteArray(int value) {
		return new byte[] { (byte) (value >>> 24), (byte) (value >>> 16),
				(byte) (value >>> 8), (byte) value };
	}

	public byte[] serialize() throws IOException {
		ByteArrayOutputStream out = new ByteArrayOutputStream();

		out.write(intToByteArray(this.len));
		out.write(intToByteArray(this.type));
		out.write(intToByteArray(this.xid));

		return out.toByteArray();
	}
}