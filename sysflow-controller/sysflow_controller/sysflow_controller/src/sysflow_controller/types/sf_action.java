package sysflow_controller.types;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.Serializable;
import java.util.Arrays;

import sysflow_controller.message.FlowModMessage;

public class sf_action implements Cloneable, Serializable {
	// kevin, variable length parameter adjustment
	public static final int			SFPA_MAX_PARAM = 1024;
	
	int action_type;
	int len;			// kevin, len is a total length of each action
	int par_len;		// kevin, par_len keeps a length of action_code
	byte[] action_code;	/*parameters for sysflow action if necessary*/
	
	
	//sysflow action type
	public static final int 		SYSFLOW_ACTION_UNKOWN = 0;
	public static final int		    SYSFLOW_ACTION_ALLOW = 1; 		
	public static final int 	    SYSFLOW_ACTION_DENY = 2; 		
	public static final int 	    SYSFLOW_ACTION_REDIRECT = 3; 		
	public static final int 	    SYSFLOW_ACTION_QRAUNTINE = 4;
	public static final int 	    SYSFLOW_ACTTION_ISOLATION = 5;
	public static final int 	    SYSFLOW_ACTION_MIGRATION = 6;
	public static final int 	    SYSFLOW_ACTION_ENCODE = 7; 
	public static final int 	    SYSFLOW_ACTION_DECODE = 8; 	
	public static final int 	    SYSFLOW_ACTION_LOG = 9; 
	public static final int 	    SYSFLOW_ACTION_REPORT = 10; 
	public static final int 	    SYSFLOW_ACTION_MESSAGE = 11; 
	public static final int 	    SYSFLOW_ACTION_NEXTMODULE = 12;
	
	public sf_action(int type, byte[] par, int par_len){
		this.action_type = type;
		
		// kevin, variable length parameter adjustment
		//this.len = par_len + Integer.BYTES * 2;
		this.action_code = new byte[SFPA_MAX_PARAM];
		
		//TODO: add exception handling
		if (par == null || par_len == 0){
			return;
		}
		
		// kevin, variable length parameter adjustment
		//this.action_code = Arrays.copyOf(par, par_len);
		for(int i=0; i<par_len && i < SFPA_MAX_PARAM; i++)
			this.action_code[i] = par[i];
		
		//this.len = par_len + Integer.BYTES * 2;
		this.par_len = FlowModMessage.pack4(par_len, SFPA_MAX_PARAM);
		this.len = this.par_len + Integer.BYTES * 2;
	}
	
	public int getLength(){
		return this.len;
	}
	
	public String toString(){
		String action = "";
		action += "Total len: " + len + " bytes, action type: " + action_type + ", action code len: " + par_len;
		
		return action + ", action code: " + new String(action_code);

		/*
		if (len - 8 > 0){
			return action;
		}
		else{
			return action + " action code: " + new String(action_code);
		}
			*/
	}
	
	/**
	 * convert integer to byte array for serialization
	 * 
	 * @param value
	 *            the value of integer
	 * @return the byte array of the input integer
	 */
	protected static final byte[] intToByteArray(int value) {
		return new byte[] { (byte) (value >>> 24), (byte) (value >>> 16),
				(byte) (value >>> 8), (byte) value };
	}

	
	public  byte[] serialize() throws IOException {
		ByteArrayOutputStream out = new ByteArrayOutputStream(this.len);
		
		out.write(intToByteArray(this.action_type));
		// kevin, second field should be the length of action code
		//out.write(intToByteArray(this.len));
		out.write(intToByteArray(this.par_len));
		// kevin, variable length parameter adjustment
		//out.write(this.action_code);
		byte[] action = new byte[this.par_len];
		for (int i = 0; i < this.par_len; i++) {
			action[i] = (byte) this.action_code[i];
		}
		out.write(action);
	   
		return out.toByteArray();
	}
}