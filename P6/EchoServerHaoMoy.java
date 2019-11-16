package P6;//package P6;//package cs4351;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Random;
import java.util.Scanner;

public class EchoServerHaoMoy {
    // This code originally was written from a piece of code written
    // by Yoonsik Cheon at least 10 years ago.
    // It was rewritten several times by Luc Longpre over the years and
    // may have reached a state that has only little resemblance to the original code.
    // This version used for Computer Security, Spring 2019

    public static void main(String[] args) {
        System.out.println("EchoServer started.");

        ObjectInputStream objectInput;
        ObjectOutputStream objectOutput;
        Cipher cipherRSA, cipherEnc, cipherDec;
        Signature sig;
        byte[] serverRandomBytes, clientRandomBytes;
        PublicKey[] pkpair;
        PrivateKey privateKeyEncrypt = PemUtils.readPrivateKey("serverRSAPrivateKey.pem", "RSA");
        PrivateKey privateKeySign = PemUtils.readPrivateKey("serverDSAPrivateKey.pem", "DSA");
        CertDetails details=new CertDetails();


        try {
            ServerSocket s = new ServerSocket(8008);
            while (true) {
                Socket incoming = s.accept();
                System.out.println("Connected to: "
                        + incoming.getInetAddress()
                        + " at port: " + incoming.getLocalPort());
                BufferedReader in = new BufferedReader(
                        new InputStreamReader(incoming.getInputStream()));
                PrintWriter out = new PrintWriter(
                        new OutputStreamWriter(incoming.getOutputStream()));

                out.print("Hello! This is Java EchoServer. ");
                out.println("Enter BYE to exit.");
                out.flush();

                String str = in.readLine();
                System.out.println(str);

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

                pkpair = VerifyRsaSignedCert.vCert(in, details);

                serverRandomBytes = new byte[8];
                new Random().nextBytes(serverRandomBytes);

                objectOutput = new ObjectOutputStream(incoming.getOutputStream());
                objectInput = new ObjectInputStream(incoming.getInputStream());

                try {
                    //encrypt randombytes
                    cipherEnc = Cipher.getInstance("RSA");
                    assert pkpair != null;
                    cipherEnc.init(Cipher.ENCRYPT_MODE, pkpair[0]);
                    //byte[] iv = cipherEnc.getIV();
                    byte[] encryptedBytes = cipherEnc.doFinal(serverRandomBytes);
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

                    //objectOutput.writeObject(iv);
                } catch (IOException e) {
                    System.out.println("error computing or sending the signature for random bytes");
                    return;
                }

                try {
                    // initialize object streams
                    // receive encrypted random bytes from server
                    byte[] encryptedBytes = (byte[]) objectInput.readObject();
                    // receive signature of hash of random bytes from server
                    byte[] signatureBytes = (byte[]) objectInput.readObject();
                    // will need to verify the signature and decrypt the random bytes

                    cipherRSA = Cipher.getInstance("RSA");
                    cipherRSA.init(Cipher.DECRYPT_MODE, privateKeyEncrypt);
                    clientRandomBytes = cipherRSA.doFinal(encryptedBytes);
                } catch (IOException | ClassNotFoundException ex) {
                    System.out.println("Problem with receiving random bytes from client");
                    return;
                }

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
                } catch (IOException | NoSuchAlgorithmException
                        | NoSuchPaddingException | InvalidKeyException e) {
                    System.out.println("error setting up the AES encryption");
                    return;
                }

                for (;;) {
                    byte[] encryptedByte = (byte[]) objectInput.readObject();
                    // decrypt the bytes
                    str = new String(cipherDec.doFinal(encryptedByte));
                    // reply to the client with an echo of the string
                    // this reply is not encrypted, you need to modify this
                    // by encrypting the reply

                    str = "Echo: " + str;
                    encryptedByte = cipherEnc.doFinal(str.getBytes());
                    objectOutput.writeObject(encryptedByte);

                    System.out.println("Received: " + str);
                    if (str.trim().equals("BYE")) {
                        break;
                    }
                }
                incoming.close();
            }
        } catch (Exception e) {
            System.out.println("Error: " + e);
        }
        System.out.println("EchoServer stopped.");
    }
}
