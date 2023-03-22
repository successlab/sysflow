package sysflow_controller.types;

/*bitwise mask for sysflow key, 
8th digit for src, 7th for dst, 6th for opcode, 5th for src_name, 4th for dst_name rest digits are reserved*/

public class sf_mask {
	int mask;
	
	public sf_mask(boolean matchSource, boolean matchDst, boolean matchOPCode, boolean matchSourceName, boolean matchDstName){
		this.mask = 0;
		
		if (matchSource){
			this.mask |= 1;
		}
		if (matchDst){
			this.mask |= 2;
		}
		if (matchOPCode){
			this.mask |= 4;
		}
		if (matchSourceName){
			this.mask |= 8;
		}
		if (matchDstName){
			this.mask |= 16;
		}
	}
	
	public int getMask(){
		return this.mask;
	}
}
