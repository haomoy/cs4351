//package cs4351;

import java.io.*;
import java.net.*;
import java.security.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;

public class EchoClientSkeleton {
    // This code includes socket code originally provided
    // by Dr. Yoonsik Cheon at least 10 years ago.
    // This version used for Computer Security, Spring 2019.    
    public static void main(String[] args) {

        String host = "localhost";
        //String host = "cspl000.utep.edu";
        BufferedReader in; // for reading strings from socket
        PrintWriter out;   // for writing strings to socket
        ObjectInputStream objectInput;   // for reading objects from socket        
        ObjectOutputStream objectOutput; // for writing objects to socket
        Cipher cipheRSA, cipherEnc;
        byte[] clientRandomBytes;
        PublicKey[] pkpair;
        Socket socket;
        // Handshake
        try {
            // socket initialization
            socket = new Socket(host, 8008);
            in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            out = new PrintWriter(new OutputStreamWriter(socket.getOutputStream()));
        } catch (IOException e) {
            System.out.println("socket initialization error");
            return;
        }
        // Send hello to server
        out.println("hello");
        out.flush();
        // Receive Server certificate
        // Will need to verify the certificate and extract the Server public keys
        try {
            String line = in.readLine();
            while (!"-----END SIGNATURE-----".equals(line)) {
                line = in.readLine();
            }
        } catch (IOException e) {
            System.out.println("problem reading the certificate from server");
            return;
        }

        try {
            // read and send certificate to server
            File file = new File("client2Certificate.txt");
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
        try {
            // initialize object streams
            objectOutput = new ObjectOutputStream(socket.getOutputStream());
            objectInput = new ObjectInputStream(socket.getInputStream());
            // receive encrypted random bytes from server
            byte[] encryptedBytes = (byte[]) objectInput.readObject();
            // receive signature of hash of random bytes from server
            byte[] signatureBytes = (byte[]) objectInput.readObject();
            // will need to verify the signature and decrypt the random bytes
            
        } catch (IOException | ClassNotFoundException ex) { 
            System.out.println("Problem with receiving random bytes from server");
            return;
        }
        // generate random bytes for shared secret
        clientRandomBytes = new byte[8];
        // the next line would initialize the byte array to random values
        // new Random().nextBytes(clientRandomBytes);
        // here we leave all bytes to zeroes.
        // The server shifts to testing mode when receiving all byte 
        // values zeroes and uses all zeroes as shared secret
        try {
            // you need to encrypt and send the the random byte array
            // here, precalculated encrypted bytes using zeroes as shared secret
            String encryptedRandomBytesString="ZHvOC9JD1lycHGU1pinu0KBDLESlWeOAnFGH4yAfvbuet1VBPZadgvDi6wN3yNVP1fD9czvWM/dbcI1IlV9obvhouGSaFJPoBiHs2gJNgckKJbSVwdKaOb3BcBmY8QWtbxUILPmvL1HL51/Yj7Kt83YD1EDoM03wH/6tiCfw6MU=";
            byte[] encryptedBytes = Base64.getDecoder().decode(encryptedRandomBytesString);
            objectOutput.writeObject(encryptedBytes);
            // you need to generate a signature of the hash of the random bytes
            // here, precalculated signature using the client private key associated with the certificate
            String signatureBytesString = "MCwCFClXIdKA5hfpndwR2QW9pPfUf+xKAhRqJnvDfpK2/Mw0vSPKlJSn/pZ9zg==";
            byte[] signatureBytes = Base64.getDecoder().decode(signatureBytesString);
            objectOutput.writeObject(signatureBytes);
        } catch (IOException e) {
            System.out.println("error computing or sending the signature for random bytes");
            return;
        }
        // initialize the shared secret with all zeroes
        // will later need to generate from a combination of the server and 
        // the client random bytes generated
        byte[] sharedSecret = new byte[16];
        //System.arraycopy(serverRandomBytes, 0, sharedSecret, 0, 8);
        //System.arraycopy(clientRandomBytes, 8, sharedSecret, 8, 8);
        try {
            // we will use AES encryption, CBC chaining and PCS5 block padding
            cipherEnc = Cipher.getInstance("AES/CBC/PKCS5Padding");            
            // generate an AES key derived from randomBytes array
            SecretKeySpec secretKey = new SecretKeySpec(sharedSecret, "AES");
            cipherEnc.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] iv = cipherEnc.getIV();
            objectOutput.writeObject(iv);
        } catch (IOException | NoSuchAlgorithmException 
                | NoSuchPaddingException | InvalidKeyException e) {
            System.out.println("error setting up the AES encryption");
            return;
        }
        try {
            // Encrypted communication
            System.out.println("Starting messages to the server. Type messages, type BYE to end");    
            Scanner userInput = new Scanner(System.in);
            boolean done = false;
            while (!done) {
                // Read message from the user
                String userStr = userInput.nextLine();
                // Encrypt the message
                byte[] encryptedBytes = cipherEnc.doFinal(userStr.getBytes());
                // Send encrypted message as an object to the server
                objectOutput.writeObject(encryptedBytes);
                // If user says "BYE", end session
                if (userStr.trim().equals("BYE")) {
                    System.out.println("client session ended");
                    done = true;
                } else {
                    // Wait for reply from server,
                    encryptedBytes = (byte[]) objectInput.readObject();
                    // will need to decrypt and print the reply to the screen
                    System.out.println("Encrypted echo received, but not decrypted");
                }
            }            
        } catch (IllegalBlockSizeException | BadPaddingException 
                | IOException | ClassNotFoundException e) {
            System.out.println("error in encrypted communication with server");
        }
    }
}
