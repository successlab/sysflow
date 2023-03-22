package sysflow_controller.denifitions;

/*controller-to-DP message: hello*/

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;

import sysflow_controller.message.FlowModMessage;
import sysflow_controller.types.sf_type_message;


public class sf_message_flow_stats_request  extends sf_message implements Cloneable{
	
	int src_len;
	int src_type;
	
	//src id (use 20 bytes to store)
	int pid;
	char[] src_name;
	
	int dst_len;
	int dst_type;
	
	//dst id (use 20 bytes to store)
	int uuid;
	int inode_num;
	char[] dst_name;
	
	//mask for 3-tuple(src, dst, opcode), TODO: finer-grained definition
	int mask;	
	int opcode;
	
	public sf_message_flow_stats_request(int mask, int opcode){
		type = sf_type_message.SFP_FLOW_STATE_REQUEST;
		
		this.mask = mask;
		this.opcode = opcode;
		
		// kevin, variable length src/dst name required
		//src_name = new char[20];
		//dst_name = new char[20];
		src_name = new char[FlowModMessage.SFPFM_MAX_NAME];
		dst_name = new char[FlowModMessage.SFPFM_MAX_NAME];
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
		type = sf_type_message.SFP_FLOW_MOD;
		
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
	
	public  byte[] serialize() throws IOException {
		ByteArrayOutputStream out = new ByteArrayOutputStream( );
		
		out.write(super.serialize());
		
		out.write(this.src_type);
		out.write(this.src_len);
		out.write(this.pid);
		
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
		
		out.write(this.dst_type);
		out.write(this.dst_len);
		out.write(this.uuid);
		out.write(this.inode_num);
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
		
		out.write(this.mask);
		out.write(this.opcode);
	
		return out.toByteArray();
	}
}
