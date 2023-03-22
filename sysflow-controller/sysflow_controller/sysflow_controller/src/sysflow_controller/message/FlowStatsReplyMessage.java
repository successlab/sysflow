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

import sysflow_controller.types.sf_action;
import sysflow_controller.types.sf_type_message;

/**
 * Represents the Flow Status Request message. This is the
 * java form of the message.
 */

public class FlowStatsReplyMessage extends SFMessage {

	int src_type;
	int src_len;
	
	//src id (use 20 bytes to store)
	int pid;
	char[] src_name = null;
	
	int dst_type;
	int dst_len;
	
	//dst id (use 20 bytes to store)
	int uuid;
	int inode_num;
	char[] dst_name = null;
	
	//mask for 3-tuple(src, dst, opcode), TODO: finer-grained definition
	int mask;	
	int opcode;
	
	//TODO: add meta-data for host module stats
	int event_count;
	int byte_count;
	
	public FlowStatsReplyMessage(){
		super();
		this.type = sf_type_message.SFP_FLOW_STATE_REPORT;
		src_name = new char[FlowModMessage.SFPFM_MAX_NAME];// kevin, variable length src/dst name
		dst_name = new char[FlowModMessage.SFPFM_MAX_NAME];
	
	}
	
    
    public String getName() {
        return "Flow Modification Message";
    }
    
    public String toString(){
String msg = "";
    	
    	msg += "Sysflow flow stats reply message\n";
    	msg += "len: " + this.len + "\n";
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
    	msg += "event_hit: " + this.event_count + "\n";
    	msg += "byte_hit: " + this.byte_count + "\n";
     	
    	return msg;
    }
    
	@Override
	public int length() {
		int len = 0;
		
		//add the header length 
		len += 3 * Integer.BYTES;
		
		//add the source entity
		//len += 3 * Integer.BYTES + 10 * Character.BYTES;
		len += 3 * Integer.BYTES + this.src_len;		// kevin, fix the src/dst length in length() of FlowStatsReply
		
		//add the destination entity
		//len += 4 * Integer.BYTES + 10 * Character.BYTES;
		len += 4 * Integer.BYTES + this.dst_len;		// kevin, fix the src/dst length in length() of FlowStatsReply
		
		//add the mask and opcode
		len += 2 * Integer.BYTES;
	
		return len;
	}
	
	public void setSource(int src_type, int src_len, int pid, char[] name){
		
		this.src_type = src_type;
		
		// kevin, pack
		this.src_len = FlowModMessage.pack4(src_len, FlowModMessage.SFPFM_MAX_NAME);
		
		this.pid = pid;
		
		//TODO: add exception handling
		if (name == null){
			return;
		}
		// kevin, variable length
		for(int i=0; i<src_len && i < FlowModMessage.SFPFM_MAX_NAME; i++)
			this.src_name[i] = name[i];
	}
	
	
	public int getSourceID(){
		return this.pid;
	}
	
	public void setDestination(int dst_type, int dst_len, int uuid, int inode, char[] name){
		super.type = sf_type_message.SFP_FLOW_STATE_REPORT;		// kevin, fixed a wrong message type (flow mod) was passed to FlowStatsRequest
		
		this.dst_type = dst_type;
		
		// kevin, variable length src/dst name required
		this.dst_len = FlowModMessage.pack4(dst_len, FlowModMessage.SFPFM_MAX_NAME);
		
		this.uuid = uuid;
		this.inode_num = inode;
		
		//TODO: add exception handling
		if (name == null){
			return;
		}
		
		// kevin, variable length src/dst name required
		for(int i=0; i<dst_len && i < FlowModMessage.SFPFM_MAX_NAME; i++)
			this.dst_name[i] = name[i];
	}
	

    /** converts the raw message into this message object */
    public void fromBytes(ByteBuffer buffer) {
    	int index = 0;
    	int pos = 0;
    	/*
    	this.len = buffer.getInt(0);
    	this.type = buffer.getInt(4);
    	this.xid = buffer.getInt(8);
    	
    	this.src_type = buffer.getInt(12);
    	this.src_len = buffer.getInt(16);
    	this.pid = buffer.getInt(20);
    	byte[] srcNameB = new byte[20];
    	buffer.get(srcNameB, 24, 20);
    	for (int i = 0; i < 20; i++){
    		this.src_name[i] = (char) srcNameB[i];
    	}
    	this.dst_type = buffer.getInt(44);
    	this.dst_len = buffer.getInt(48);
    	this.uuid = buffer.getInt(52);
    	this.inode_num = buffer.getInt(56);
    	byte[] dstNameB = new byte[20];
    	buffer.get(dstNameB, 60, 20);
    	for (int i = 0; i < 20; i++){
    		this.dst_name[i] = (char) dstNameB[i];
    	}
    	
    	this.mask = buffer.getInt(80);
    	this.opcode = buffer.getInt(84);
    	
    	this.event_count = buffer.getInt(88);
    	this.byte_count = buffer.getInt(92);
    	*/
    	
    	
    	// kevin, variable length src/dst name
    	this.len = buffer.getInt(index);
    	index += 4;
    	this.type = buffer.getInt(index);
    	index += 4;
    	this.xid = buffer.getInt(index);
    	index += 4;
    	
    	this.src_type = buffer.getInt(index);
    	index += 4;
    	this.src_len = buffer.getInt(index);
    	index += 4;
    	this.pid = buffer.getInt(index);
    	index += 4;
    	
    	// kevin, ByteBuffer buffer.get() causes unexpected IndexOutOfBoundsExcmeption
    	/*
    	if(this.src_len > 0) {
    		byte[] srcNameB = new byte[this.src_len];
    		buffer.get(srcNameB, index, this.src_len);
    		for (int i = 0; i < this.src_len; i++){
    			this.src_name[i] = (char) srcNameB[i];
    		}
    	}
    	*/
    	// workaround solution
    	for (int i = 0; i < index; i++)
			buffer.get();
		for (int i = 0; i < this.src_len; i++)
	         	this.src_name[i] = (char)buffer.get();
    	
    	index += this.src_len;
    	pos += index;
    	
    	this.dst_type = buffer.getInt(index);
    	index += 4;
    	this.dst_len = buffer.getInt(index);
    	index += 4;
    	this.uuid = buffer.getInt(index);
    	index += 4;
    	this.inode_num = buffer.getInt(index);
    	index += 4;
    	
    	// kevin, ByteBuffer buffer.get() causes unexpected IndexOutOfBoundsExcmeption
    	/*
    	if(this.dst_len > 0) {
    		byte[] dstNameB = new byte[this.dst_len];
    		buffer.get(dstNameB, index, this.dst_len);
    		for (int i = 0; i < this.dst_len; i++){
    			this.dst_name[i] = (char) dstNameB[i];
    		}
    	}
    	*/
    	// kevin, workaround solution
		for (int i = pos; i < index; i++)
			buffer.get();
		for (int i = 0; i < this.dst_len; i++)
	         	this.dst_name[i] = (char)buffer.get();
		
    	index += this.dst_len;
    	
    	this.mask = buffer.getInt(index);
    	index += 4;
    	this.opcode = buffer.getInt(index);
    	index += 4;
    	
    	this.event_count = buffer.getInt(index);
    	index += 4;
    	this.byte_count = buffer.getInt(index);
    	
    }
    
    public void fromBytes(ByteBuf buffer) {
    	int index = 0;
    	/*
    	this.len = buffer.getInt(0);
    	this.type = buffer.getInt(4);
    	this.xid = buffer.getInt(8);
    	
    	this.src_type = buffer.getInt(12);
    	this.src_len = buffer.getInt(16);
    	this.pid = buffer.getInt(20);
    	byte[] srcNameB = new byte[20];
    	buffer.getBytes(24, srcNameB, 0, 20);
    	for (int i = 0; i < 20; i++){
    		this.src_name[i] = (char) srcNameB[i];
    	}
    	this.dst_type = buffer.getInt(44);
    	this.dst_len = buffer.getInt(48);
    	this.uuid = buffer.getInt(52);
    	this.inode_num = buffer.getInt(56);
    	byte[] dstNameB = new byte[20];
    	buffer.getBytes(60, dstNameB, 0, 20);
    	for (int i = 0; i < 20; i++){
    		this.dst_name[i] = (char) dstNameB[i];
    	}
    	
    	this.mask = buffer.getInt(80);
    	this.opcode = buffer.getInt(84);
    	
    	this.event_count = buffer.getInt(88);
    	this.byte_count = buffer.getInt(92);
    	*/
    	// kevin, variable length src/dst name
    	this.len = buffer.getInt(index);
    	index += 4;
    	this.type = buffer.getInt(index);
    	index += 4;
    	this.xid = buffer.getInt(index);
    	index += 4;
    	
    	this.src_type = buffer.getInt(index);
    	index += 4;
    	this.src_len = buffer.getInt(index);
    	index += 4;
    	this.pid = buffer.getInt(index);
    	index += 4;
    	
    	// kevin outofbound exception in fromBytes(ByteBuf buffer) of FlowStatsReply
    	if(this.src_len > 0) {
    		byte[] srcNameB = new byte[this.src_len];
    		buffer.getBytes(index, srcNameB, 0, this.src_len);
    		for (int i = 0; i < this.src_len; i++){
    			this.src_name[i] = (char) srcNameB[i];
    		}
    	}
    	index += this.src_len;
    	
    	this.dst_type = buffer.getInt(index);
    	index += 4;
    	this.dst_len = buffer.getInt(index);
    	index += 4;
    	this.uuid = buffer.getInt(index);
    	index += 4;
    	this.inode_num = buffer.getInt(index);
    	index += 4;
    	
    	// kevin outofbound exception in fromBytes(ByteBuf buffer) of FlowStatsReply
    	if(this.dst_len > 0) {
    		byte[] dstNameB = new byte[this.dst_len];
    		buffer.getBytes(index, dstNameB, 0, this.dst_len);
    		for (int i = 0; i < this.dst_len; i++){
    			this.dst_name[i] = (char) dstNameB[i];
    		}
    	}
    	index += this.dst_len;
    	
    	this.mask = buffer.getInt(index);
    	index += 4;
    	this.opcode = buffer.getInt(index);
    	index += 4;
    	
    	this.event_count = buffer.getInt(index);
    	index += 4;
    	this.byte_count = buffer.getInt(index);
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
		// kevin, variable length
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
		
		// kevin, variable length
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


}