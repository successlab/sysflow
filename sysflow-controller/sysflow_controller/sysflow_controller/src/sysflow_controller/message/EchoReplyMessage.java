package sysflow_controller.message;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;

import io.netty.buffer.ByteBuf;

public class EchoReplyMessage extends SFMessage {

	public EchoReplyMessage(){
		super();
	}
	
	public EchoReplyMessage(int xid){
		this.type = SFMessageType.SFP_ECHO_REPLY;
		this.xid = xid;
		this.len = this.length();
	}
	
    public String getName() {
        return "Echo Reply Message";
    }
    
    public String toString(){
    	return "Echo Reply message " + " xid: " + this.xid + " len: " + this.len;
    }
    
	@Override
	public void fromBytes(ByteBuffer message) {
		this.len = lenFromMsg(message);
    	this.type = typeFromMsg(message);
    	this.xid = xidFromMsg(message);

	}

	@Override
	public void fromBytes(ByteBuf message) {
		this.len = lenFromMsg(message);
    	this.type = typeFromMsg(message);
    	this.xid = xidFromMsg(message);

	}

	@Override
	public int length() {
		return 3 * Integer.BYTES;
	}

	@Override
	public void toBytes(ByteBuffer buffer) throws IOException {
		bytesToMsg(buffer, this.serialize());

	}
	
	public  byte[] serialize() throws IOException {
		ByteArrayOutputStream out = new ByteArrayOutputStream( );
		
		out.write(super.serialize());
	   
		return out.toByteArray();
	}

}
