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
import sysflow_controller.types.sf_action;
import sysflow_controller.types.sf_type_message;

/**
 * Represents the Flow Status Request message. This is the
 * java form of the message.
 */
public class FlowStatsRequestMessage extends SFMessage {

	int src_type;
	int src_len;
	
	//src id (use 20 bytes to store)
	// kevin, revised to variable length
	int pid;
	char[] src_name = null;
	
	int dst_type;
	int dst_len;
	
	//dst id (use 20 bytes to store)
	// kevin, revised to variable length
	int uuid;
	int inode_num;
	char[] dst_name = null;
	
	//mask for 3-tuple(src, dst, opcode), TODO: finer-grained definition
	int mask;	
	int opcode;
	
	public FlowStatsRequestMessage(int mask, int opcode){
		// kevin, fix a wrong message type (flow mod) was passed to FlowStatsRequest
		//this.type = sf_type_message.SFP_FLOW_MOD;
		this.type = sf_type_message.SFP_FLOW_STATE_REQUEST;
		
		// kevin, use xids pool
		//this.xid = 0;
		this.xid = SFChannelHandler.getNewXid();
		
		this.mask = mask;
		this.opcode = opcode;
		
		// kevin, variable length src/dst name required
		//src_name = new char[20];
		//dst_name = new char[20];
		src_name = new char[FlowModMessage.SFPFM_MAX_NAME];
		dst_name = new char[FlowModMessage.SFPFM_MAX_NAME];
		
		this.len = this.length();
	}
	

    public String getName() {
        return "Flow Stats Request Message";
    }
    
    
    
	@Override
	public int length() {
		int len = 0;
		
		//add the header length 
		len += 3 * Integer.BYTES;
		
		// kevin, variable length src/dst name required
		/*
		//add the source entity
		len += 3 * Integer.BYTES + 10 * Character.BYTES;
		
		//add the destination entity
		len += 4 * Integer.BYTES + 10 * Character.BYTES;
		*/
		// src match
		len += 3 * Integer.BYTES + src_len;
		// dst match
		len += 4 * Integer.BYTES + dst_len;
		
		//add the mask and opcode
		len += 2 * Integer.BYTES;
	
		return len;
	}
	
	public void setSource(int src_type, int src_len, int pid, char[] name){
		this.src_type = src_type;
		
		// kevin, variable length src/dst name required
		//this.src_len = src_len;
		this.src_len = FlowModMessage.pack4(src_len, FlowModMessage.SFPFM_MAX_NAME);
		
		this.pid = pid;
		
		//TODO: add exception handling
		if (name == null){
			return;
		}
		
		// kevin, variable length src/dst name required
		//this.src_name = Arrays.copyOf(name, 20);
		for(int i=0; i<src_len && i < FlowModMessage.SFPFM_MAX_NAME; i++)
			this.src_name[i] = name[i];
	}
	
	public void setDestination(int dst_type, int dst_len, int uuid, int inode, char[] name){
		type = sf_type_message.SFP_FLOW_STATE_REQUEST;		// kevin, fixed a wrong message type (flow mod) was passed to FlowStatsRequest
		
		this.dst_type = dst_type;
		
		// kevin, variable length src/dst name required
		//this.dst_len = dst_len;
		this.dst_len = FlowModMessage.pack4(dst_len, FlowModMessage.SFPFM_MAX_NAME);
		
		this.uuid = uuid;
		this.inode_num = inode;
		
		//TODO: add exception handling
		if (name == null){
			return;
		}
		
		// kevin, variable length src/dst name required
		//this.dst_name = Arrays.copyOf(name, 20);
		for(int i=0; i<dst_len && i < FlowModMessage.SFPFM_MAX_NAME; i++)
			this.dst_name[i] = name[i];
	}

	
    /** converts the raw message into this message object */
    public void fromBytes(ByteBuffer message) {
    	//TODO no need for such function since the controller does not parse flow-mod message
    }
    
    public void fromBytes(ByteBuf message) {
    	//TODO no need for such function since the controller does not parse flow-mod message
    }
    
    
    /** converts the message into raw bytes. 
     * @throws IOException */
    public void toBytes(ByteBuffer buffer) throws IOException {
        bytesToMsg(buffer, this.serialize());
    }
    
    public  byte[] serialize() throws IOException {
		ByteArrayOutputStream out = new ByteArrayOutputStream( );
		
		out.write(super.serialize());
		
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
			srcName[i] = (byte) dst_name[i];
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
		
		return out.toByteArray();
	}


	@Override
	public String toString(){
		String msg = "";
		
		msg += "Sysflow flow stats request message\n";
		msg += "len: " + this.len + "\n";
		msg += "message type: " + this.type + "\n";			//kevin, add a message type
		msg += "xid: " + this.xid + "\n";
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
	
		return msg;
	}
	


}