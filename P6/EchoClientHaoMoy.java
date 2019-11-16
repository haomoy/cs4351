package P6;//package cs4351;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.Socket;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Random;
import java.util.Scanner;

public class EchoClientHaoMoy {
    // This code includes socket code originally provided
    // by Dr. Yoonsik Cheon at least 10 years ago.
    // This version used for Computer Security, Spring 2019.
    public static void main(String[] args) throws IOException {

        String host = "localhost";
        //String host = "cspl000.utep.edu";
        BufferedReader in; // for reading strings from socket
        PrintWriter out;   // for writing strings to socket
        ObjectInputStream objectInput;   // for reading objects from socket
        ObjectOutputStream objectOutput; // for writing objects to socket
        Cipher cipherRSA, cipherEnc, cipherDec;
        Signature sig;
        byte[] serverRandomBytes = new byte[8], clientRandomBytes;
        PublicKey[] pkpair;
        PrivateKey privateKeyEncrypt = PemUtils.readPrivateKey("clientRSAPrivateKey.pem", "RSA");
        PrivateKey privateKeySign = PemUtils.readPrivateKey("clientDSAPrivateKey.pem", "DSA");
        CertDetails details = new CertDetails();
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

        in.readLine();
        pkpair = VerifyRsaSignedCert.vCert(in, details);

        try {
            // read and send certificate to server
            File file = new File("clientCertificate.txt");
            Scanner input = new Scanner(file);
            String line;
            while (input.hasNextLine()) {
                line = input.nextLine();
                out.println(line);
            }
            out.flush();
        } catch (FileNotFoundException e) {
            System.out.println("certificate file not found");
            return;
        }

        // initialize object streams
        objectOutput = new ObjectOutputStream(socket.getOutputStream());
        objectInput = new ObjectInputStream(socket.getInputStream());

        try {
            // receive encrypted random bytes from server
            byte[] encryptedBytes = (byte[]) objectInput.readObject();
            // receive signature of hash of random bytes from server
            byte[] signatureBytes = (byte[]) objectInput.readObject();
            // will need to verify the signature and decrypt the random bytes
            //byte[] iv = (byte[]) objectInput.readObject();
            cipherRSA = Cipher.getInstance("RSA");

            assert pkpair != null;
            cipherRSA.init(Cipher.DECRYPT_MODE, privateKeyEncrypt);
            serverRandomBytes = cipherRSA.doFinal(encryptedBytes);
        } catch (IOException | ClassNotFoundException ex) {
            System.out.println("Problem with receiving random bytes from server");
            return;
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
        }

        // generate random bytes for shared secret
        clientRandomBytes = new byte[8];
        new Random().nextBytes(clientRandomBytes);

        try {
            // encrypt random bytes
            cipherEnc = Cipher.getInstance("RSA");
            assert pkpair != null;
            cipherEnc.init(Cipher.ENCRYPT_MODE, pkpair[0]);
            byte[] encryptedBytes = cipherEnc.doFinal(clientRandomBytes);
            objectOutput.writeObject(encryptedBytes);

            // generate signature
            // hash randombytes with SHA-256
            // sign with "SHA1withDSA"
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(encryptedBytes);

            sig = Signature.getInstance("SHA1withDSA");
            sig.initSign(privateKeySign);

            byte[] signatureBytes = cipherEnc.doFinal(hash);
            objectOutput.writeObject(signatureBytes);
        } catch (IOException e) {
            System.out.println("error computing or sending the signature for random bytes");
            return;
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | BadPaddingException | IllegalBlockSizeException | InvalidKeyException e) {
            e.printStackTrace();
        }
        // initialize the shared secret with all zeroes
        // will later need to generate from a combination of the server and
        // the client random bytes generated
        byte[] sharedSecret = new byte[serverRandomBytes.length+clientRandomBytes.length];
        System.arraycopy(serverRandomBytes, 0, sharedSecret, 0, serverRandomBytes.length);
        System.arraycopy(clientRandomBytes, 0, sharedSecret, serverRandomBytes.length, clientRandomBytes.length);
        try {
            // we will use AES encryption, CBC chaining and PCS5 block padding
            cipherEnc = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipherDec = Cipher.getInstance("AES/CBC/PKCS5Padding");
            // generate an AES key derived from randomBytes array
            SecretKeySpec secretKey = new SecretKeySpec(sharedSecret, "AES");
            cipherEnc.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] iv = cipherEnc.getIV();
            objectOutput.writeObject(iv);
            byte[] iv2 = (byte[]) objectInput.readObject();
            cipherDec.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv2));
        } catch (IOException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | ClassNotFoundException e) {
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
                    String str = new String(cipherDec.doFinal(encryptedBytes));
                    System.out.println(str);
                }
            }
        } catch (IllegalBlockSizeException | BadPaddingException
                | IOException | ClassNotFoundException e) {
            System.out.println("error in encrypted communication with server");
        }
    }
}
