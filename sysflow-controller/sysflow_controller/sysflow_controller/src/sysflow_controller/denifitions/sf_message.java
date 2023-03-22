package sysflow_controller.denifitions;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

public class sf_message {
	protected int len;
	protected int type;
	
    public static int getLength() {
        return Byte.SIZE * 2;
    }
    
    public int getType() {
    	return this.type;
    	          
    }
    
    public void setType(byte type) {
        this.type = type;
    }
    
    public  byte[] serialize() throws IOException {
		ByteArrayOutputStream out = new ByteArrayOutputStream( );
		
		out.write(this.type);
		out.write(this.len);
		   
		return out.toByteArray();
	}
}

