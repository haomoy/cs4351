//package cs4351;
import java.io.*;
import java.security.*;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;


public class HaoMoyServerEncryptPrivate {

  public static void main(String[] args) throws IOException  {
	  CreatePemDSAKeys serverDSAKey = new CreatePemDSAKeys();
  	  CreatePemRSAKeys serverRSAKey = new CreatePemRSAKeys();
	  
  	  serverDSAKey.main(null);
  	  serverRSAKey.main(null);
  	  
	  try (ServerSocket listener = new ServerSocket(59090)) {
          System.out.println("The date server is running...");
          while (true) {
              try (Socket socket = listener.accept()) {
            	  PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
                  out.println("Hello There");
              }
          }
      }
  }
}