package sysflow_controller.message;

import io.netty.buffer.ByteBuf;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.util.logging.Logger;
import java.nio.ByteBuffer;
import java.util.TimeZone;

/**
 * Represents the Hello message that can be sent to the server. This is the
 * java form of the message.
 */
public class HelloMessage extends SFMessage {

	public HelloMessage(){
		super();
	}
	
	public HelloMessage(int xid){
		this.type = SFMessageType.SFP_HELLO;
		this.xid = xid;
		this.len = this.length();
	}
	
    public String getName() {
        return "Hello Message";
    }
    
    public String toString(){
    	return "Hello message " + " xid : " + this.xid + " len :" + this.len + "\n";
    }
    
	@Override
	public int length() {
		return 3 * Integer.BYTES;
	}
    
    /** converts the raw message into this message object */
    public void fromBytes(ByteBuffer message) {
    	this.len = lenFromMsg(message);
    	this.type = typeFromMsg(message);
    	this.xid = xidFromMsg(message);
    }
    
    public void fromBytes(ByteBuf message) {
    	this.len = lenFromMsg(message);
    	this.type = typeFromMsg(message);
    	this.xid = xidFromMsg(message);
    }

    /** converts the message into raw bytes. 
     * @throws IOException */
    public void toBytes(ByteBuffer buffer) throws IOException {
        bytesToMsg(buffer, this.serialize());
    }
    
    public  byte[] serialize() throws IOException {
		ByteArrayOutputStream out = new ByteArrayOutputStream( );
		
		out.write(super.serialize());
	   
		return out.toByteArray();
	}


}