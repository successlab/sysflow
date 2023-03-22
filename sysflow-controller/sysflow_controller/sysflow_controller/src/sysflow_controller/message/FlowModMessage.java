package sysflow_controller.message;

import io.netty.buffer.ByteBuf;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.util.logging.Logger;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.TimeZone;

import sysflow_controller.core.SFChannelHandler;
import sysflow_controller.test.testController.HostState;
import sysflow_controller.types.sf_action;
import sysflow_controller.types.sf_type_message;

/**
 * Represents the Flow Modification message. This is the java form of the
 * message.
 */

public class FlowModMessage extends SFMessage {

	/* sysflow flow mod type */
	public static final int SFPFM_ADD = 0;
	public static final int SFPFM_REMOVE = 1;
	public static final int SFPFM_UPDATE = 2;
	
	// kevin, variable length src/dst name required
	public static final int SFPFM_MAX_NAME = 1024;

	//type of flow mod
	int fm_type;
	
	int src_type;
	int src_len;

	// src id (use 20 bytes to store)
	int pid;
	char[] src_name = null;

	int dst_type;
	int dst_len;

	// dst id (use 20 bytes to store)
	int uuid;
	int inode_num;
	char[] dst_name = null;

	// mask for 3-tuple(src, dst, opcode), TODO: finer-grained definition
	int mask;
	int opcode;

	int priority;
	
	int action_len; // the number of actions
	sf_action[] actions = null; // the maximum action is 5 // FIXME: should define the max value


	
	public FlowModMessage(int fm_type, int priority, int mask, int opcode) {
		this.type = sf_type_message.SFP_FLOW_MOD;
		// kevin, use xids pool
		//this.xid = 0;
		this.xid = SFChannelHandler.getNewXid();
		
		//default FlowMod type is ADD, use set flow mod type to change
		this.fm_type = fm_type; 
		
		
		this.mask = mask;
		this.opcode = opcode;
		this.priority = priority;
		
		// kevin, variable length src/dst name required
		//src_name = new char[20];
		//dst_name = new char[20];
		src_name = new char[SFPFM_MAX_NAME];
		dst_name = new char[SFPFM_MAX_NAME];
		
		action_len = 0;
		actions = new sf_action[5];		// kevin, FIXME: max value should be defined

		this.len = this.length();
	}

	public String getName() {
		return "Flow Modification Message";
	}

	public void setFlowModType (int type){
		this.fm_type = type;
	}
	
	@Override
	public int length() {
		int len = 0;

		// add the header length
		len += 3 * Integer.BYTES;
		
		// add flow mod type length
		len += Integer.BYTES;
		
		// kevin, variable length src/dst name required
		/*
		// add the source entity
		len += 3 * Integer.BYTES + 20 * 1;

		// add the destination entity
		len += 4 * Integer.BYTES + 20 * 1;
		*/
		// add the source entity
		//len += 3 * Integer.BYTES + src_name.length * 1;
		len += 3 * Integer.BYTES + src_len;		// kevin, return a correct length

		// add the destination entity
		//len += 4 * Integer.BYTES + dst_name.length * 1;
		len += 4 * Integer.BYTES + dst_len;	// kevin, return a correct length
		
		

		// add the mask, opcode and priority
		len += 3 * Integer.BYTES;
		
		// kevin, missing action_len
		len += Integer.BYTES;

		// add the action length
		for (int i = 0; i < action_len; i++) {
			len += actions[i].getLength();
		}
		

		return len;
	}
	
	// kevin, pack out bytes for variable length data
	public static int pack4(int buflen, int maxlen) {
		if(0 == buflen % Integer.BYTES) {
			return buflen;
		}
		else {
			// 9%4 = 1, 10%4 = 2, 11%4 = 3
			int newlen = buflen + Integer.BYTES - (buflen % Integer.BYTES);
			if(newlen > maxlen) {
				return maxlen;
			}
			else {
				return newlen;
			}
		}
	}

	public void setSource(int src_type, int src_len, int pid, char[] name) {
		this.src_type = src_type;
		// kevin, variable length src/dst name required
		//this.src_len = src_len;
		this.src_len = pack4(src_len, SFPFM_MAX_NAME);
				
		this.pid = pid;

		// TODO: add exception handling
		if (name == null) {
			return;
		}

		// kevin, variable length src/dst name required
		//this.src_name = Arrays.copyOf(name, 20);	
		for(int i=0; i<src_len && i < SFPFM_MAX_NAME; i++)
			this.src_name[i] = name[i];
	}

	public void setDestination(int dst_type, int dst_len, int uuid, int inode,
			char[] name) {
		type = sf_type_message.SFP_FLOW_MOD;

		this.dst_type = dst_type;
		// kevin, variable length src/dst name required
		//this.dst_len = dst_len;
		this.dst_len = pack4(dst_len, SFPFM_MAX_NAME);

		this.uuid = uuid;
		this.inode_num = inode;

		// TODO: add exception handling
		if (name == null) {
			return;
		}
		
		// kevin, variable length src/dst name required
		//this.dst_name = Arrays.copyOf(name, 20);
		for(int i=0; i<dst_len && i < SFPFM_MAX_NAME; i++)
			this.dst_name[i] = name[i];
	}

	public void addAction(sf_action action) {
		if (action_len >= 5) {
			return;
		}

		this.actions[action_len] = action;
		
		action_len += 1;

		// adjust the len
		this.len = this.length();
	}

	/** converts the raw message into this message object */
	public void fromBytes(ByteBuffer message) {
		// TODO no need for such function since the controller does not parse
		// flow-mod message
	}

	public void fromBytes(ByteBuf message) {
		// TODO no need for such function since the controller does not parse
		// flow-mod message
	}

	/**
	 * converts the message into raw bytes.
	 * 
	 * @throws IOException
	 */
	public void toBytes(ByteBuffer buffer) throws IOException {
		bytesToMsg(buffer, this.serialize());
	}

	@Override
	public String toString() {
		String msg = "";

		msg += "Sysflow flow mod message\n";
		msg += "len: " + this.length() + "\n";				// kevin, fix it to return a correct length
		msg += "message type: " + this.type + "\n";
		msg += "xid: " + this.xid + "\n";
		msg += "flow mod type: " + this.fm_type + "\n";
		msg += "src_type: " + this.src_type + "\n";
		msg += "src_len: " + this.src_len + "\n";
		msg += "pid:" + this.pid + "\n";
		msg += "src_name:" + new String(this.src_name) + "\n";
		msg += "dst_type: " + this.dst_type + "\n";
		msg += "dst_len: " + this.dst_len + "\n";
		msg += "uuid: " + this.uuid + "\n";
		msg += "inode: " + this.inode_num + "\n";
		msg += "dst_name:" + new String(this.dst_name) + "\n";
		msg += "mask: " + this.mask + "\n";
		msg += "opcode: " + this.opcode + "\n";			
		msg += "priority: " + this.priority + "\n";			// kevin, change in order
		
		msg += "action_len: " + this.action_len + "\n";
		

		for (int i = 0; i < action_len; i++) {
			msg += actions[i].toString() + "\n";
		}

		return msg;
	}

	public byte[] serialize() throws IOException {
		ByteArrayOutputStream out = new ByteArrayOutputStream();

		out.write(super.serialize());

		out.write(intToByteArray(this.fm_type));
		out.write(intToByteArray(this.src_type));
		out.write(intToByteArray(this.src_len));
		out.write(intToByteArray(this.pid));
		
		// kevin, variable length src/dst name required
		/*
		byte[] srcName = new byte[20];
		for (int i = 0; i < 20; i++) {
			srcName[i] = (byte) src_name[i];
		}
		out.write(srcName);
		*/
		byte[] srcName = new byte[this.src_len];
		for (int i = 0; i < this.src_len; i++) {
			srcName[i] = (byte) this.src_name[i];
		}
		out.write(srcName);

		out.write(intToByteArray(this.dst_type));
		out.write(intToByteArray(this.dst_len));
		out.write(intToByteArray(this.uuid));
		out.write(intToByteArray(this.inode_num));
		// kevin, variable length src/dst name required
		/*
		byte[] dstName = new byte[20];
		for (int i = 0; i < 20; i++) {
			dstName[i] = (byte) dst_name[i];
		}
		out.write(dstName);
		*/
		byte[] dstName = new byte[this.dst_len];
		for (int i = 0; i < this.dst_len; i++) {
			dstName[i] = (byte) this.dst_name[i];
		}
		out.write(dstName);
		
		
		
		
		

		out.write(intToByteArray(this.mask));
		out.write(intToByteArray(this.opcode));
		out.write(intToByteArray(this.priority));

		out.write(intToByteArray(action_len));
		for (int i = 0; i < action_len; i++) {
			out.write(actions[i].serialize());
		}

		return out.toByteArray();
	}

}