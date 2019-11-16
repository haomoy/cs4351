//package cs4351;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;
import java.util.stream.Stream;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.stream.Stream;

public class EchoServerSkelleton {
    // The MultiEchoServer was provided by Yoonsik Cheon at least 10 years ago.
    // It was modified several times by Luc Longpre over the years.
    // This version is augmented by encrypting messages using AES encryption.
    // Used for Computer Security, Spring 2019.
    public static void main(String[] args) {

        String host = "localhost";
        //String host = "cspl000.utep.edu";
        ObjectInputStream objectInput;   // for reading objects from client
        ObjectOutputStream objectOutput; // for writing objects to client
        Cipher cipheRSA, cipherEnc;
        byte[] clientRandomBytes;
        PublicKey[] pkpair;
        Socket socket;

        System.out.println("EchoServerSkelleton started.");
        int sessionID = 0; // assign incremental session ids to each client connection

        try {
            ServerSocket s = new ServerSocket(8008);
            // The server runs until an error occurs
            // or is stopped externally
            for (;;) {
                Socket incoming = s.accept();
                // start a connection with the client
                // in a new thread and wait for another
                // connection
                new ClientHandler(incoming, ++sessionID).start();
                // start() causes the thread to begin execution
                // the JVM calls the run() method of this thread
            }
        } catch (Exception e) {
            System.out.println("Error: " + e);
        }
        System.out.println("MultiEchoServer stopped.");
    }

    private static class ClientHandler extends Thread {


        BufferedReader in; // for reading strings from client
        PrintWriter out;   // for writing strings to client

        protected Socket incoming;
        protected int id;

        public ClientHandler(Socket incoming, int id) {
            this.incoming = incoming;
            this.id = id;
        }

        public void run() {
            try {
                // in and out for socket communication using strings
                in = new BufferedReader(
                        new InputStreamReader(incoming.getInputStream()));
                out = new PrintWriter(
                        new OutputStreamWriter(incoming.getOutputStream()));

                //Receive hello from client
                String h = in.readLine();
                //Print hello in console
                System.out.println(h);

                //String builder to retrieve certificate contents
                try {
                    // read and send certificate to server
                    File file = new File("serverCertificate.txt");
                    Scanner input = new Scanner(file);
                    String line;
                    while (input.hasNextLine()) {
                        line = input.nextLine();
                        out.println(line);
                    }
                    out.flush();
                } catch (FileNotFoundException e){
                    System.out.println("certificate file not found");
                    return;
                }

                // We could use Base64 encoding and communicate with strings using in and out
                // However, we show here how to send and receive serializable java objects                    
                ObjectInputStream objectInput = new ObjectInputStream(incoming.getInputStream());
                ObjectOutputStream objectOutput = new ObjectOutputStream(incoming.getOutputStream());
                // read the file of random bytes from which we can derive an AES key
                byte[] randomBytes;


                try {
                    FileInputStream fis = new FileInputStream("randomBytes");
                    randomBytes = new byte[fis.available()];
                } catch (Exception e) {
                    //System.out.println(System.getProperty("user.dir"));
                    System.out.println("problem reading the randomBytes file");

                    return;
                }

                // get the initialization vector from the client
                // each client will have a different vector
                byte[] iv = (byte[]) objectInput.readObject();
                // we will use AES encryption, CBC chaining and PCS5 block padding
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                // generate an AES key derived from randomBytes array
                SecretKeySpec secretKey = new SecretKeySpec(randomBytes, "AES");
                // initialize with a specific vector instead of a random one
                cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));

                // keep echoing the strings received until
                // receiving the string "BYE" which will break
                // out of the for loop and close the thread
                for (;;) {
                    // get the encrypted bytes from the client as an object
                    byte[] encryptedByte = (byte[])objectInput.readObject();

                    // decrypt the bytes
                    String str = new String(cipher.doFinal(encryptedByte));

                    // reply to the client with an echo of the string
                    // this reply is not encrypted, you need to modify this
                    // by encrypting the reply
                    objectOutput.reset();
                    objectOutput.writeObject(encryptedByte);

                    // Commented by Hao
                    //String str2 = new String(cipher2.doFinal(encryptedByte));
                    /*
                    String echo = "Echo: ";
                    String reply = echo.concat(str);
                    Cipher cipher2 = Cipher.getInstance("AES/CBC/PKCS5Padding");
                    cipher2.init(Cipher.ENCRYPT_MODE, secretKey);
                    byte[] bytesReply = reply.getBytes();
                    //cipher2.update(bytesReply);
                    byte[] encryptedReply = cipher2.doFinal(bytesReply);
                    System.out.println("Before dec " + encryptedReply);
                    */
                    /*
                    Cipher seoncdCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                    seoncdCipher.init(Cipher.ENCRYPT_MODE, secretKey);
                    objectOutput.writeObject(iv); 
                    objectOutput.close();
                    */

                    // print the message received from the client
                    System.out.println("Received from session " + id + ": " + str);
                    if (str.trim().equals("BYE")) {
                        break;
                    }
                }
                System.out.println("Session " + id + " ended.");
                incoming.close();
            } catch (Exception e) {
                System.out.println("Error: " + e);
                e.printStackTrace();
            }
        }
    }
}