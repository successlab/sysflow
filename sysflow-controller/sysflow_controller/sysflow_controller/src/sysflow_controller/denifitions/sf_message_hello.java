package sysflow_controller.denifitions;

/*controller-to-DP message: hello*/

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import sysflow_controller.types.sf_type_message;

public class sf_message_hello  extends sf_message implements Cloneable{
	
	public sf_message_hello(){
		type = sf_type_message.SFP_HELLO;
		len = super.getLength();
	}
	
	public  byte[] serialize() throws IOException {
		ByteArrayOutputStream out = new ByteArrayOutputStream( );
		
		out.write(super.serialize());
	   
		return out.toByteArray();
	}
}
