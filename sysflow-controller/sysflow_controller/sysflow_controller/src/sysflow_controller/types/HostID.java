package sysflow_controller.types;

import java.net.SocketAddress;

/**
 * use hashcode of IP address as Host ID
 * @author ray
 *
 */
public class HostID {
	
	/*The ID of a sysflow-eanble host, currently,
	 * we use hashcode of IP address*/
//	int id;
	
	String id;
	
	
	
	public HostID(String addr){
		this.id = addr;
//		this.id = addr.hashCode();
		
	}
	
	/**
	 * set host ID
	 * @param hid Integer of host ID
	 */
	//public HostID(int hid){
	//	this.id = hid;
	//}

	/**
	 * get host ID
	 * @return Integer of host ID
	 */
	public String getHostID(){
		return this.id;
		
	}

	
	public String toString(){
		return this.id;
		
	}
}
