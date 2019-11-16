package P6;
import java.io.*;
import java.security.*;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Scanner;
import java.net.InetAddress;
import java.net.Socket;
import java.io.IOException;

/**
 * A command line client for the server. Requires the IP address of
 * the server as the sole argument. Exits after printing the response.
 */
public class HaoMoyClientSignPublic {
    public static void main(String[] args) throws IOException {
    	CreatePemDSAKeys clientDSAKey = new CreatePemDSAKeys();
    	CreatePemRSAKeys clientRSAKeys = new CreatePemRSAKeys();
    	
    	clientDSAKey.main(null);
    	clientRSAKeys.main(null);
    	
    	InetAddress localhost = InetAddress.getLocalHost(); 

        Socket socket = new Socket("localhost", 59090);
        Scanner in = new Scanner(socket.getInputStream());
        System.out.println("Server response: " + in.nextLine());
    }
}