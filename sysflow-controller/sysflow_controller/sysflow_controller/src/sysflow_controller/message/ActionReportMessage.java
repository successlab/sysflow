package sysflow_controller.message;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;

import io.netty.buffer.ByteBuf;
import sysflow_controller.types.sf_type_message;

/**
 * kevin, this class represents Action Report message. 
 * 
 * @Format:
 * 			header {length, type, xid}
 * 			match.src {src_type, src_len, pid, src_name}
 * 			match.dst {dst_type, dst_len, file_id(uuid, inode#), dst_name, mask, opcode}
 * 			match.mask
 * 			match.opcode
 * 			action_type
 * 			reason
 * 			data_len
 * 			data 
 */
public class ActionReportMessage extends SFMessage {
	public static final int SFPACT_MAX_DATA = 256;
	
	// header from SFMessage
	
	// match.src
	int src_type;
	int src_len;
	
	int pid;
	char[] src_name = null;
	
	// match.dst
	int dst_type;
	int dst_len;
	
	//dst id (use 20 bytes to store)
	int uuid;
	int inode_num;
	char[] dst_name = null;
	
	//mask for 3-tuple(src, dst, opcode), TODO: finer-grained definition
	int mask;	
	int opcode;
	
	int action_type;
	int reason;
	int data_len;
	byte[] data = null;
	
	ActionReportMessage() {
		super();
		this.type = sf_type_message.SFP_ACTION_REPORT;
		src_name = new char[FlowModMessage.SFPFM_MAX_NAME];
		dst_name = new char[FlowModMessage.SFPFM_MAX_NAME];
		data = new byte[SFPACT_MAX_DATA];
	}
	
	public String getName() {
        return "Action Report Message";
    }

    public String getData() { return new String(this.data);}

    public String toString(){
    	String msg = "";
    	
    	msg += "Sysflow action report message\n";
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
    	msg += "action_type: " + this.action_type + "\n";
    	msg += "reason: " + this.reason + "\n";
    	msg += "data_len: " + this.data_len + "\n";
    	msg += "data: ";
    	for(int i = 0; i < this.data_len ; i++) {
            msg += this.data[i] + " ";
         }
    	msg += "\nstring data: " + new String(this.data);
    	
    	return msg;
    }
    
	@Override
	public void fromBytes(ByteBuffer buffer) {
		int index = 0;
		
		//System.out.println("************************* buffer size: " + buffer.get)
		
    	// header
    	this.len = buffer.getInt(index);
    	index += 4;
    	this.type = buffer.getInt(index);
    	index += 4;
    	this.xid = buffer.getInt(index);
    	index += 4;
    	// match.src
    	this.src_type = buffer.getInt(index);
    	index += 4;
    	this.src_len = buffer.getInt(index);
    	index += 4;
    	this.pid = buffer.getInt(index);
    	index += 4;
    	
    	System.out.println("************************* src_len: " + this.src_len);
    	
    	if(this.src_len > 0) {
    		/*
    		byte[] srcNameB = new byte[this.src_len];
    		buffer.get(srcNameB, index, this.src_len);
    		for (int i = 0; i < this.src_len; i++){
    			this.src_name[i] = (char) srcNameB[i];
    		}
    		*/
    		for (int i = 0; i < this.src_len; i++) {
   	         	//this.src_name[i] = (char)buffer.get();
    			this.src_name[i] = (char)buffer.get(index+i);
    		}
    	}
    	index += this.src_len;
    	
    	// match.dst
    	this.dst_type = buffer.getInt(index);
    	index += 4;
    	this.dst_len = buffer.getInt(index);
    	index += 4;
    	this.uuid = buffer.getInt(index);
    	index += 4;
    	this.inode_num = buffer.getInt(index);
    	index += 4;
    	
    	System.out.println("************************* dst_len: " + this.dst_len);
    	
    	if(this.dst_len > 0) {
    		// kevin, ByteBuffer buffer.get() causes unexpected IndexOutOfBoundsExcmeption
    		//byte[] dstNameB = new byte[this.dst_len];
    		/*
    		buffer.get(dstNameB, index, this.dst_len);
    		for (int i = 0; i < this.dst_len; i++){
    			this.dst_name[i] = (char) dstNameB[i];
    		}
    		*/
    		
    		for (int i = 0; i < this.dst_len; i++) {
    	         //this.dst_name[i] = (char)buffer.get();
    	         this.dst_name[i] = (char)buffer.get(index+i);
    		}
    	}
    	System.out.println("########## dst_name: " + new String(this.dst_name));
    	index += this.dst_len;
    	
    	this.mask = buffer.getInt(index);
    	index += 4;
    	this.opcode = buffer.getInt(index);
    	index += 4;
    	
    	this.action_type = buffer.getInt(index);
    	index += 4;
    	this.reason = buffer.getInt(index);
    	index += 4;
    	this.data_len = buffer.getInt(index);
    	index += 4;
    	
    	
    	System.out.println("************************* action_type: " + this.action_type);
    	System.out.println("************************* reason: " + this.reason);
    	System.out.println("************************* data_len: " + this.data_len);
    	
    	if(this.data_len > 0) {
    		// kevin, ByteBuffer buffer.get() causes unexpected IndexOutOfBoundsExcmeption
    		/*
    		byte[] report_data = new byte[this.data_len];
    		buffer.get(report_data, index, this.data_len);
    		for (int i = 0; i < this.data_len; i++){
    			this.data[i] = report_data[i];
    		}
    		*/
    		// kevin, workaround solution
    		for (int i = 0; i < index; i++)
    			buffer.get();
    		for (int i = 0; i < this.data_len; i++)
   	         	this.data[i] = buffer.get();
    	}
	}

	@Override
	public void fromBytes(ByteBuf buffer) {
		int index = 0;
    	// header
    	this.len = buffer.getInt(index);
    	index += 4;
    	this.type = buffer.getInt(index);
    	index += 4;
    	this.xid = buffer.getInt(index);
    	index += 4;
    	// match.src
    	this.src_type = buffer.getInt(index);
    	index += 4;
    	this.src_len = buffer.getInt(index);
    	index += 4;
    	this.pid = buffer.getInt(index);
    	index += 4;
    	
    	if(this.src_len > 0) {
    		byte[] srcNameB = new byte[this.src_len];
    		buffer.getBytes(index, srcNameB, 0, this.src_len);
    		for (int i = 0; i < this.src_len; i++){
    			this.src_name[i] = (char) srcNameB[i];
    		}
    	}
    	index += this.src_len;
    	
    	// match.dst
    	this.dst_type = buffer.getInt(index);
    	index += 4;
    	this.dst_len = buffer.getInt(index);
    	index += 4;
    	this.uuid = buffer.getInt(index);
    	index += 4;
    	this.inode_num = buffer.getInt(index);
    	index += 4;
    	
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
    	
    	this.action_type = buffer.getInt(index);
    	index += 4;
    	this.reason = buffer.getInt(index);
    	index += 4;
    	this.data_len = buffer.getInt(index);
    	index += 4;
    	
    	if(this.data_len > 0) {
    		byte[] report_data = new byte[this.data_len];
    		buffer.getBytes(index, report_data, 0, this.data_len);
    		for (int i = 0; i < this.data_len; i++){
    			this.data[i] = report_data[i];
    		}
    	}

	}

	@Override
	public int length() {
		int len = 0;
		
		//add the header length 
		len += 3 * Integer.BYTES;
		
		//add the source entity
		len += 3 * Integer.BYTES + this.src_len;		
		
		//add the destination entity
		len += 4 * Integer.BYTES + this.dst_len;		
		
		//add the mask and opcode
		len += 2 * Integer.BYTES;
		
		// add action_type, reason, data_len
		len += 3 * Integer.BYTES;
		
		// add data size
		len += this.data_len;
	
		return len;
	}

	@Override
	public void toBytes(ByteBuffer buffer) throws IOException {
		bytesToMsg(buffer, this.serialize());
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
		super.type = sf_type_message.SFP_ACTION_REPORT;		// kevin, fixed a wrong message type (flow mod) was passed to FlowStatsRequest
		
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
	
	public  byte[] serialize() throws IOException {
		ByteArrayOutputStream out = new ByteArrayOutputStream( );
		
		// header
		out.write(super.serialize());
		
		// match.src
		out.write(intToByteArray(this.src_type));
		out.write(intToByteArray(this.src_len));
		out.write(intToByteArray(this.pid));
		if(this.src_len > 0) {
			byte[] srcName = new byte[this.src_len];
			for (int i = 0; i < this.src_len; i++) {
				srcName[i] = (byte) this.src_name[i];
			}
			out.write(srcName);
		}
		
		// match.dst
		out.write(intToByteArray(this.dst_type));
		out.write(intToByteArray(this.dst_len));
		out.write(intToByteArray(this.uuid));
		out.write(intToByteArray(this.inode_num));
		if(this.dst_len > 0) {
			byte[] dstName = new byte[this.dst_len];
			for (int i = 0; i < this.dst_len; i++) {
				dstName[i] = (byte) this.dst_name[i];
			}
			out.write(dstName);
		}
		
		out.write(intToByteArray(this.mask));
		out.write(intToByteArray(this.opcode));
		
		// int action_type;
		out.write(intToByteArray(this.action_type));
		out.write(intToByteArray(this.reason));
		out.write(intToByteArray(this.data_len));
		if(this.data_len > 0) {
			byte[] report_data = new byte[this.data_len];
			for (int i = 0; i < this.data_len; i++) {
				report_data[i] = (byte) this.data[i];
			}
			out.write(report_data);
		}
		
		
		return out.toByteArray();
	}
}
