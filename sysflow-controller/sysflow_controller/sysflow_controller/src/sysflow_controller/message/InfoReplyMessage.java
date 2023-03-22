package sysflow_controller.message;

import io.netty.buffer.ByteBuf;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.util.logging.Logger;
import java.nio.ByteBuffer;
import java.util.TimeZone;

import sysflow_controller.types.sf_type_OS;

/**
 * Represents the Host Information Request message that can be sent to the server. This is the
 * java form of the message.
 */
public class InfoReplyMessage extends SFMessage {
	
	//host profile received from data plane
	private byte[] hostID; //use 6 bytes mac address
	private int osType;
	private int coreNum; 
	
	
	public InfoReplyMessage(){
		super();
		
		hostID = new byte[6];
		osType = 0;
		coreNum = 0;
	}
	
	
	
    @Override
    public String toString() {
        return "Host Information Reply Message\n" + "Host ID: " + hostID + "\nOS Type: " + osType + "\nCore Num: " + coreNum + "\n";
    }
    
	@Override
	public int length() {
		return 3 * Integer.BYTES;
	}
	
	/**
	 * retrieve the core number from the info reply message		
	 * @return the number of CPU cores
	 */
	public int getCoreNum(){
		return this.coreNum;
	}
	
	/**
	 * retrieve the operating system type from the info reply message		
	 * @return the type of the operating system
	 */
	public int getOSType(){
		return this.osType;
	}
	
	/**
	 * retrieve the host ID (mac address) in byte array format from the info reply message
	 * @return the byte array of host ID (mac address)
	 */
	public byte[] getHostID(){
		return this.hostID;
	}
	

	
    /**	
     * @param buffer the message buffer
     * @return the length of the message
     */
    public static int lenFromMsg(ByteBuffer buffer){
    	int len = buffer.getInt(0);
    	return len;
    }
    
    /**	
     * @param buffer the message buffer
     * @return the type of the message
     */
    public static int typeFromMsg(ByteBuffer buffer){
    	int type = buffer.getInt(4);
    	return type;
    }
    
    /**	
     * @param buffer the message buffer
     * @return the transmission id of the message
     */
    public static int xidFromMsg(ByteBuffer buffer){
    	int xid = buffer.getInt(8);
    	return xid;
    }
    
    /**
     * information reply message specific field
     * @param buffer the message buffer
     * @return the host ID of the message
     */
    public static byte[] hostIDFromMsg(ByteBuffer buffer){
    	byte[] hostID = new byte[6];
    	buffer.get(hostID, 12, 6);
    	return hostID;
    }

    public static byte[] hostIDFromMsg(ByteBuf buffer){
    	byte[] hostID = new byte[6];
    	buffer.getBytes(12, hostID, 0, 6);
    	return hostID;
    }
    
    /**	
     * information reply message specific field
     * @param buffer the message buffer
     * @return the os type from information reply message
     */
    public static int osTypeFromMsg(ByteBuffer buffer){
    	int osType = buffer.getInt(18);
    	return osType;
    }
    
    public static int osTypeFromMsg(ByteBuf buffer){
    	int osType = buffer.getInt(18);
    	return osType;
    }
    
    /**
     * information reply message specific field
     * @param buffer the message buffer
     * @return the CPU core number from information reply messages
     */
    public static int coreNumFromMsg(ByteBuffer buffer){
    	int coreNum = buffer.getInt(22);
    	return coreNum;
    }
    
    public static int coreNumFromMsg(ByteBuf buffer){
    	int coreNum = buffer.getInt(22);
    	return coreNum;
    }
	
    /** converts the raw message into this message object */
    public void fromBytes(ByteBuffer buffer) {
    	//System.out.println(buffer.remaining());
    	
    	this.len = buffer.getInt();
    	
    	this.type = buffer.getInt();
    	this.xid = buffer.getInt();
    	
    	this.osType = buffer.getInt();
    	this.coreNum = buffer.getInt();
    	
    	//System.out.println(buffer.remaining());
    	/*
    	this.len = lenFromMsg(buffer);
    	this.type = typeFromMsg(buffer);
    	this.xid = xidFromMsg(buffer);
    	
    	this.hostID = hostIDFromMsg(buffer);
    	this.osType = osTypeFromMsg(buffer);
    	this.coreNum = coreNumFromMsg(buffer);
    	*/
    }
    
    public void fromBytes(ByteBuf message) {
    	this.len = lenFromMsg(message);
    	this.type = typeFromMsg(message);
    	this.xid = xidFromMsg(message);
    	
    	this.hostID = hostIDFromMsg(message);
    	this.osType = osTypeFromMsg(message);
    	this.coreNum = coreNumFromMsg(message);
    }
    
    
    /** converts the message into raw bytes. 
     * @throws IOException */
    public void toBytes(ByteBuffer buffer) throws IOException {
       //TODO controller does not need to send information reply msg
    }
    
    public  byte[] serialize() throws IOException {
		ByteArrayOutputStream out = new ByteArrayOutputStream( );
		
		out.write(super.serialize());
		out.write(this.hostID);
		out.write(this.intToByteArray(this.osType));
		out.write(this.intToByteArray(this.coreNum));
	   
		return out.toByteArray();
	}

}