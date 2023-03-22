package sysflow_controller.test;

import java.net.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.util.logging.Logger;
import java.io.*;

import sysflow_controller.message.FlowModMessage;
import sysflow_controller.message.FlowStatsReplyMessage;
import sysflow_controller.message.FlowStatsRequestMessage;
import sysflow_controller.message.HelloMessage;
import sysflow_controller.message.InfoReplyMessage;
import sysflow_controller.message.InfoRequestMessage;
import sysflow_controller.message.SFMessage;
import sysflow_controller.types.sf_action;
import sysflow_controller.types.sf_mask;
import sysflow_controller.types.sf_type_match;
import sysflow_controller.types.sf_type_operation;

public class testController {
	private final static int SERVER_PORT = 5000;
	private final static int SOCKET_BUFFER = 2000;
	
	private final static Logger logger = Logger.getLogger("SysFlow Controller");
	
    /* Module Loader State */
    private static HostState hostState;
    public enum HostState {
        INIT, STARTUP, COMPLETE
    }
	
	public static void main(String args[]){
		 ServerSocket server = null;
		 
		 if (args.length == 0){
			 System.out.println("Usage: java testController <mode>");
			 System.out.println("1 : test receiving hello messgage");
			 System.out.println("2 : test sending hello messgage");
			 System.out.println("3 : test sending info request messgage");
			 System.out.println("4 : test receiving info reply messgage");
			 System.out.println("5 : test sending flow mod messgage");
			 System.out.println("6 : test sending flow stats request messgage");
			 System.out.println("7 : test receiving flow stats reply messgage");
			 System.exit(0);
		 }
		 
		 String testMode = null;
		 if (args.length != 0)
			 testMode = args[0];
		 
		 try {
			 ServerSocketChannel serverSocket = ServerSocketChannel.open();
			 serverSocket.bind(new InetSocketAddress("localhost", SERVER_PORT));
			 logger.info("Listening on " + SERVER_PORT);
			 
             SocketChannel socket = serverSocket.accept();
             
             SFMessage msg = null;
             switch(testMode){
             case "1": // test receive hello
            	 System.out.println("test receive hello");
            	 msg = getMessage(socket);
            	 //handle sysflow message
     	         if (msg != null && msg instanceof HelloMessage){
     	        	 System.out.println("Pass test of receivng hello message!");
     	        	 System.out.println(msg.toString());
     	         }
     	         else{
     	        	 System.out.println("failed test: the received msg is not hello.");
     	         }
     	     break;
     	     
             case "2": // test send hello
            	 System.out.println("test send hello");
            	 testInstallHello(socket);
             break;
             
             case "3": // test send info request
            	 System.out.println("test send info request");
            	 testInstallInfoRequest(socket);
             break;
             
             case "4": // test receive info reply
            	 System.out.println("test receive info reply");
            	 msg = getMessage(socket);
            	 //handle sysflow message
     	         if (msg != null && msg instanceof InfoReplyMessage){
     	        	 System.out.println("Pass test of receivng info reply message!");
     	         }
     	         else{
     	        	 System.out.println("failed test: the received msg is not info rely.");
     	         } 
             break;
             
             case "5": // test send flow mod
            	 System.out.println("test send flow mod");
            	 testInstallFlowMod(socket);
             break;
             
             case "6":
            	 System.out.println("test send flow stats request.");
            	 testInstallFlowStatsRequest(socket);
             break;
             
             case "7":
            	 System.out.println("test receive flow stats report");
            	 msg = getMessage(socket);
            	 //handle sysflow message
     	         if (msg != null && msg instanceof FlowStatsReplyMessage){
     	        	 System.out.println("Pass test of receivng flow stats reply message!");
     	        	System.out.println(msg.toString());
     	         }
     	         else{
     	        	 System.out.println("failed test: the received msg is not flow stats rely.");
     	         }
     	      break;
             }

            
			
		 }
		 catch (SocketException e) {
			 System.out.println("Socket: " + e.getMessage());
		 }
		 catch (IOException e) {
			 System.out.println("IO:  "+ e.getMessage());
		 }
		 catch (Exception e){
			 System.out.println("Exception:  "+ e.getMessage());
		 }
	}
	
	private static void testInstallHello(SocketChannel socket){
		HelloMessage helloMsg = new HelloMessage(101);
		
		System.out.println(helloMsg.toString());         
     
		 try {
			installMessage(socket, helloMsg);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	private static void testInstallInfoRequest(SocketChannel socket){
		InfoRequestMessage infoRequest = new InfoRequestMessage(22);
		
		System.out.println(infoRequest.toString());       
         
		 try {
			installMessage(socket, infoRequest);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}	
	}
	
	
	private static void testInstallFlowMod(SocketChannel socket){
		FlowModMessage flowMod = new FlowModMessage(0, 1,
        		 new sf_mask(true,true,true, false, false).getMask(), sf_type_operation.SYSFLOW_FILE_READ);
         int pid = 1001;
         flowMod.setSource(sf_type_match.SFP_MATCH_ID, 0, 1001, null);
         int inode = 2;
         int uuid = 3;
         flowMod.setDestination(sf_type_match.SFP_MATCH_ID, 0, uuid, inode, null);
         flowMod.addAction(new sf_action(sf_action.SYSFLOW_ACTION_DENY, null, 0));
         
     
		 try {
			installMessage(socket, flowMod);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}	
	}
	
	
	private static void testInstallFlowStatsRequest(SocketChannel socket){
		FlowStatsRequestMessage statsReq = new FlowStatsRequestMessage(
        		 new sf_mask(true,true,true, false, false).getMask(), sf_type_operation.SYSFLOW_FILE_READ);
         int pid = 1001;
         statsReq.setSource(sf_type_match.SFP_MATCH_ID, 0, 1001, null);
         int inode = 2;
         int uuid = 3;
         statsReq.setDestination(sf_type_match.SFP_MATCH_ID, 0, uuid, inode, null);
         
         
         
     
		 try {
			installMessage(socket, statsReq);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}	
	}

	private static void installMessage(SocketChannel socket, SFMessage outMsg) throws IOException{
		SFMessage.sendMessage(socket, outMsg);
	}
	
	/**
	 * function to handle SysFlow message
	 * @param inMsg the SysFlow message parsed from socket input buffer
	 * @throws IOException
	 * 
	 * TODO: implement SysFlow protocol state machine
	 */
	private static void handleMessage(SocketChannel socket, SFMessage inMsg) throws IOException{
		 if(inMsg == null) {
	            throw new IOException("Parsing null SysFlow message. ");
	     }
		 
		 SFMessage outMsg = null;
		 
		  if (inMsg instanceof HelloMessage){
			  //TODO: send out hello message
			  outMsg = new InfoRequestMessage(inMsg.getXid());
			  
			 logger.info("Length of sendout msg: " + outMsg.getLength());

			  SFMessage.sendMessage(socket, outMsg);
			  logger.info("send out Host Information Request message.");
	      }
		  else if (inMsg instanceof InfoReplyMessage){
			  
		  }
		  else{
			  logger.severe("Unexpected incoming message " + inMsg);
		  }
	}
	
	private static SFMessage getMessage(SocketChannel socket) throws IOException {
	        
			ByteBuffer dataBuffer = ByteBuffer.allocate(2048);
	        
			/*
			InetSocketAddress socketAddr = (InetSocketAddress) socket.getRemoteAddress();
			InetAddress hostAddr = socketAddr.getAddress();
			*/	
					
	        //convert to little endian order
	        dataBuffer.order(ByteOrder.LITTLE_ENDIAN);
	        
	        // it's customary to log out who's just connected.
	        logger.info("Socket opened to " + socket.getRemoteAddress());
	        
	        SFMessage msg = SFMessage.getMessageFromSocket(socket, dataBuffer);
	       
	        return msg;
	 }
	 
	 /**
     *  Updates handled by the main loop
     */
     public interface IUpdate {
        /**
         * Calls the appropriate listeners
         */
        public void dispatch();
     }
    
    
}
