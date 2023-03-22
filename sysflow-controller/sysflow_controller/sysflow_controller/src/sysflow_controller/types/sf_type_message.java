package sysflow_controller.types;

public class sf_type_message {
	public static final int SFP_HELLO = 0;
	public static final int SFP_INFO_REQUEST = 1;
	public static final int SFP_INFO_REPLY = 2;
	public static final int SFP_FLOW_MOD = 3;
	public static final int SFP_FLOW_STATE_REQUEST = 4;
	public static final int SFP_FLOW_STATE_REPORT = 5;
	public static final int SFP_ECHO_REQUEST = 6;		// kevin, add ECHO messages to avoid idle disconnection
	public static final int SFP_ECHO_REPLY = 7;			// kevin, add ECHO messages to avoid idle disconnection
	public static final int SFP_ACTION_REPORT = 8;		// kevin, add ACTION_REPORT message
}
