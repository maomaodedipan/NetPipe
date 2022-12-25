import java.io.*;
import java.io.FileInputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.*;
import java.sql.Timestamp;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;


public class ClientHandshake {

    HandshakeCertificate clientCA;
    HandshakeCertificate clientUser;
    HandshakeCertificate serverUser;
    byte[] clientHelloDigest;
    byte[] sessionDigset;
    byte[] serverHelloDigest;
    byte[] clientPrivateKey;

    SessionCipher sessionEncrypter;
    SessionCipher sessionDecrypter;




    /*
     * ClientHandshake initialization
     */
    public ClientHandshake(Socket socket,Arguments arguments) throws NoSuchAlgorithmException, IOException, CertificateException, ClassNotFoundException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, InvalidKeySpecException, BadPaddingException, InvalidKeyException {
        certInitialize(arguments);
        ClientHelloHandshake(socket);
        ServerHelloHandshake(socket);
        SessionHandshake(socket);
        ServerFinishHandshake(socket);
        ClientFinishHandshake(socket);
    }

    /*
     * certificate initialization
     * deal with files
     */
    public void certInitialize(Arguments arguments) throws IOException, CertificateException {
        FileInputStream userInstream = new FileInputStream(arguments.get("usercert"));
        FileInputStream caInstream = new FileInputStream(arguments.get("cacert"));
        clientUser = new HandshakeCertificate(userInstream);
        clientCA = new HandshakeCertificate(caInstream);
        FileInputStream in = new FileInputStream(arguments.get("key"));
        clientPrivateKey = in.readAllBytes();
    }

    /*
     * ClientHelloHandshake
     * Client send hello to Sever
     */
    public void ClientHelloHandshake(Socket socket) throws CertificateException, IOException, NoSuchAlgorithmException {
        HandshakeMessage handshakeMessage = new HandshakeMessage(HandshakeMessage.MessageType.CLIENTHELLO);
        String certString = Base64.getEncoder().encodeToString(clientUser.getBytes());
        handshakeMessage.putParameter("Certificate",certString);
        try {
            handshakeMessage.send(socket);
        }
        catch (Exception e){
            System.out.println("send client hello error");
        }
        clientHelloDigest = handshakeMessage.getBytes();

    }

    /*
     * ServerHelloHandshake
     * Client receive hello from Sever
     */
    public void ServerHelloHandshake(Socket socket) throws CertificateException, IOException, ClassNotFoundException, NoSuchAlgorithmException {
        HandshakeMessage handshakeMessage = HandshakeMessage.recv(socket);
        HandshakeDigest handshakeDigest =new HandshakeDigest();
        if(handshakeMessage.getType().equals(HandshakeMessage.MessageType.SERVERHELLO)){
            String certificate = handshakeMessage.getParameter("Certificate");
            System.out.println(certificate);
            serverUser = new HandshakeCertificate(Base64.getDecoder().decode(certificate));
            try {
                clientCA.verify(clientCA);
            }
            catch (Exception e){
                System.err.println("clientCA verify fail");
            }
            try {
                serverUser.verify(clientCA);
            }
            catch (Exception e){
                System.err.println("serveruser verify fail");
            }
            handshakeDigest.update(handshakeMessage.getBytes());
            serverHelloDigest = handshakeDigest.digest();
        }
        else {
            System.err.println("type error");
            socket.close();
        }


    }

    /*
     * SessionHandshake
     * Send the key and IV (Initialisation Vector) for the session
     */
    public void SessionHandshake(Socket socket) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidAlgorithmParameterException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException {
        HandshakeMessage handshakeMessage = new HandshakeMessage(HandshakeMessage.MessageType.SESSION);
        SessionKey sessionKey = new SessionKey(128);
        sessionEncrypter =new SessionCipher(sessionKey);
        byte[] sessionkeyBytes = sessionKey.getKeyBytes();
        byte[] sessionIVBytes = sessionEncrypter.getIVBytes();
        HandshakeCrypto handshakeCrypto = new HandshakeCrypto(serverUser);
        byte[] sessionkeyEncry = handshakeCrypto.encrypt(sessionkeyBytes);
        byte[] sessionIVEncry = handshakeCrypto.encrypt(sessionIVBytes);
        sessionDecrypter = new SessionCipher(sessionKey, sessionIVBytes, false);
        handshakeMessage.putParameter("SessionKey", Base64.getEncoder().encodeToString(sessionkeyEncry));
        handshakeMessage.putParameter("SessionIV", Base64.getEncoder().encodeToString(sessionIVEncry));
        handshakeMessage.send(socket);
        sessionDigset = handshakeMessage.getBytes();
    }

    /*
     * ClientfinishHandshake
     * Send the signature and timestamp
     */
    public void ClientFinishHandshake(Socket socket) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, IOException {
        HandshakeMessage handshakeMessage = new HandshakeMessage(HandshakeMessage.MessageType.CLIENTFINISHED);
        HandshakeDigest handshakeDigest = new HandshakeDigest();
        handshakeDigest.update(clientHelloDigest);
        handshakeDigest.update(sessionDigset);
        HandshakeCrypto handshakeCrypto = new HandshakeCrypto(clientPrivateKey);
        handshakeMessage.putParameter("Signature",Base64.getEncoder().encodeToString(handshakeCrypto.encrypt(handshakeDigest.digest())));
        Timestamp timestamp = new Timestamp(System.currentTimeMillis());
        byte[] timestampUTF8 = timestamp.toString().substring(0,19).getBytes(StandardCharsets.UTF_8);
        handshakeMessage.putParameter("TimeStamp",Base64.getEncoder().encodeToString(handshakeCrypto.encrypt(timestampUTF8)));
        handshakeMessage.send(socket);
    }

    /*
     * Server finishHandshake
     * Receive the signature and timestamp from server
     */
    public void ServerFinishHandshake(Socket socket) throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, IOException, ClassNotFoundException {
        HandshakeMessage handshakeMessage = HandshakeMessage.recv(socket);
        HandshakeCrypto handshakeCrypto = new HandshakeCrypto(serverUser);
        if(handshakeMessage.getType().equals(HandshakeMessage.MessageType.SERVERFINISHED)){
            byte[] getsign = Base64.getMimeDecoder().decode(handshakeMessage.getParameter("Signature"));
            byte[] signdecry = handshakeCrypto.decrypt(getsign);
            if (!Arrays.equals(signdecry, serverHelloDigest)) {
                System.err.println("verify wrong");
            }
        }

    }

}
