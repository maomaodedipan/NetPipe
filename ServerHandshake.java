import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.*;
import java.sql.Timestamp;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class ServerHandshake {
    HandshakeCertificate serverCA;
    HandshakeCertificate serverUser;
    HandshakeCertificate clientUser;
    byte[] serverHelloDigest;
    byte[] clientHelloDigest;
    byte[] sessionDigest;
    byte[] serverPrivateKey;
    byte[] sessionKeyBytes;
    byte[] sessionIVBytes;
    SessionCipher sessionEncrypter;
    SessionCipher sessionDecrypter;

    /*
     * ClientHandshake initialization
     */
    public  ServerHandshake(Socket socket,Arguments arguments) throws CertificateException, IOException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, InvalidKeySpecException, InvalidAlgorithmParameterException, ClassNotFoundException {
        certInitialize(arguments);
        ClientHelloHandshake(socket);
        ServerHelloHandshake(socket);
        SessionHandShake(socket);
        ServerFinishHandShake(socket);
        ClientFinishHandshake(socket);
    }

    /*
     * certificate initialization
     * deal with files
     */
    public void certInitialize(Arguments arguments) throws IOException, CertificateException {
        FileInputStream userInstream = new FileInputStream(arguments.get("usercert"));
        FileInputStream caInstream = new FileInputStream(arguments.get("cacert"));
        serverUser = new HandshakeCertificate(userInstream);
        serverCA = new HandshakeCertificate(caInstream);
        FileInputStream in = new FileInputStream(arguments.get("key"));
        serverPrivateKey = in.readAllBytes();
    }

    /*
     * ClientHelloHandshake
     * Server receive hello from client
     */
    public void ClientHelloHandshake(Socket socket) throws CertificateException, IOException, ClassNotFoundException {
        HandshakeMessage handshakeMessage = HandshakeMessage.recv(socket);
        System.out.println(handshakeMessage.getParameter("Certificate"));
        if(handshakeMessage.getType().equals(HandshakeMessage.MessageType.CLIENTHELLO)){
            String certificate = handshakeMessage.getParameter("Certificate");
            clientUser = new HandshakeCertificate(Base64.getDecoder().decode(certificate));
            try {
                serverCA.verify(serverCA);
            }
            catch (Exception e){
                 System.err.println("serverCA verify fail");
            }
            try {
                clientUser.verify(serverCA);
            }
            catch (Exception e){
                System.err.println("client user verify fail");
            }
            clientHelloDigest = handshakeMessage.getBytes();
        }
    }

    /*
     * ServerHelloHandshake
     * Server send hello to client
     */
    public void ServerHelloHandshake(Socket socket) throws CertificateEncodingException, IOException {
        HandshakeMessage handshakeMessage = new HandshakeMessage(HandshakeMessage.MessageType.SERVERHELLO);
        String certString = Base64.getEncoder().encodeToString(serverUser.getBytes());
        handshakeMessage.putParameter("Certificate",certString);
        System.out.println(certString);
        try {
            handshakeMessage.send(socket);
        }
        catch (Exception e){
            System.out.println("send server hello error");
        }
        serverHelloDigest = handshakeMessage.getBytes();
    }

    /*
     * SessionHandshake
     * Receive the key and IV (Initialisation Vector) for the session
     */
    public void SessionHandShake(Socket socket) throws IOException, InvalidAlgorithmParameterException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, ClassNotFoundException, InvalidKeySpecException {
        HandshakeMessage handshakeMessage = HandshakeMessage.recv(socket);
        if(handshakeMessage.getType().equals(HandshakeMessage.MessageType.SESSION)){
            HandshakeCrypto handshakeCrypto = new HandshakeCrypto(serverPrivateKey);
            try {
                sessionKeyBytes = handshakeCrypto.decrypt(Base64.getDecoder().decode(handshakeMessage.getParameter("SessionKey")));
            }
            catch (Exception e){
                System.err.println("Session key decryption error");
            }
            try {
                sessionIVBytes = handshakeCrypto.decrypt(Base64.getDecoder().decode(handshakeMessage.getParameter("SessionIV")));
            }
            catch (Exception e){
                System.err.println("SessionIV decryption error");
            }
            sessionDigest = handshakeMessage.getBytes();
            SessionKey sessionKey = new SessionKey(sessionKeyBytes);
            sessionEncrypter = new SessionCipher(sessionKey, sessionIVBytes, true);
            sessionDecrypter = new SessionCipher(sessionKey, sessionIVBytes, false);

        }
    }

    /*
     * ClientfinishHandshake
     * Receive the signature and timestamp
     */
    public void ClientFinishHandshake(Socket socket) throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, IOException, ClassNotFoundException {
        HandshakeMessage handshakeMessage =HandshakeMessage.recv(socket);
        System.out.println("receive client finish");
        if(handshakeMessage.getType().equals(HandshakeMessage.MessageType.CLIENTFINISHED)){
            HandshakeDigest handshakeDigest = new HandshakeDigest();
            handshakeDigest.update(clientHelloDigest);
            handshakeDigest.update(sessionDigest);
            HandshakeCrypto handshakeCrypto =new HandshakeCrypto(clientUser);
            if(handshakeMessage.getType().equals(HandshakeMessage.MessageType.CLIENTFINISHED)){
                byte[] getsign = Base64.getMimeDecoder().decode(handshakeMessage.getParameter("Signature"));
                byte[] signdecry = handshakeCrypto.decrypt(getsign);
                if (!Arrays.equals(signdecry, handshakeDigest.digest())) {
                    System.err.println("verify wrong");
                }
            }
        }
    }

    /*
     * ServerfinishHandshake
     * Send the signature and timestamp
     */
    public void ServerFinishHandShake(Socket socket) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, IOException {
        HandshakeMessage handshakeMessage = new HandshakeMessage(HandshakeMessage.MessageType.SERVERFINISHED);
        HandshakeDigest handshakeDigest = new HandshakeDigest();
        handshakeDigest.update(serverHelloDigest);
        HandshakeCrypto handshakeCrypto =new HandshakeCrypto(serverPrivateKey);
        handshakeMessage.putParameter("Signature",Base64.getEncoder().encodeToString(handshakeCrypto.encrypt(handshakeDigest.digest())));
        Timestamp timestamp = new Timestamp(System.currentTimeMillis());
        byte[] timestampUTF8 = timestamp.toString().substring(0,19).getBytes(StandardCharsets.UTF_8);
        handshakeMessage.putParameter("TimeStamp",Base64.getEncoder().encodeToString(handshakeCrypto.encrypt(timestampUTF8)));
        handshakeMessage.send(socket);
    }



}
