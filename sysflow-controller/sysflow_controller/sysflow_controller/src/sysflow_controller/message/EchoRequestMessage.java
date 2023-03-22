package sysflow_controller.message;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;

import io.netty.buffer.ByteBuf;

public class EchoRequestMessage extends SFMessage {

	public EchoRequestMessage(){
		super();
	}
	
	public EchoRequestMessage(int xid){
		this.type = SFMessageType.SFP_ECHO_REQUEST;
		this.xid = xid;
		this.len = this.length();
	}
	
    public String getName() {
        return "Echo Request Message";
    }
    
    public String toString(){
    	return "Echo Request message " + " xid: " + this.xid + " len: " + this.len;
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
