package sysflow_controller.types;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import sysflow_controller.core.Controller;

public class File {
	
	private static final Logger log = LoggerFactory.getLogger(File.class);

	//the max length of file name is 20 bytes
	private final int MAX_NAME_LENGTH = 20;
	private final int INVALID_ID = -1;
	
	private char[] name;
	private int nameLen;
	
	//IDs for file
	private int uuid;
	private int inode;
	
	//if the file is okay for flowMod msg
	boolean isValid;
	
	public File(){
		name = new char[20];
		nameLen = 0;
		uuid = INVALID_ID;
		inode = INVALID_ID;
		isValid = false;
	}
	
	public File(String nameS){
		if (nameS == null || nameS.length() == 0){
			log.warn("Invalid file name: too small.");
			return;
		}
		else if (nameS.length() > 20){
			log.warn("Invalid file name: large the maximum file len 20.");
			return;
		}
		
		this.nameLen = nameS.length();
		this.name = nameS.toCharArray();
		uuid = INVALID_ID;
		inode = INVALID_ID;
		this.isValid = true;
	}
	
	public File(int uuid, int inode){
		name = new char[20];
		nameLen = 0;
		this.uuid = uuid;
		this.inode = inode;
		isValid = true;
	}
	
	public void setID(int uuid, int inode){
		this.uuid = uuid;
		this.inode = inode;
		isValid = true;
	}
	
	public int getUUID(){
		return this.uuid;
	}
	
	public int getInodeNum(){
		return this.inode;
	}
	
	/**
	 * judge if the File is valid to set as sysflow FlowMod msg entity
	 * @return
	 */
	public boolean isValid(){
		return this.isValid;
	}
	
	@Override
	public String toString(){
		String string = "";
		if (name != null && nameLen > 0)
		{
			string += "The file name is " + name.toString();
		}
		if (uuid != INVALID_ID){
			string += " UUID: " + uuid;
		}
		if (inode != INVALID_ID){
			string += " Inode number: " + inode;
		}	
		return string;
	}
	
	
}
