import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class HandshakeDigest {
    MessageDigest messageDigest;
    byte[] input;

    /*
     * Constructor -- initialise a digest for SHA-256
     */

    public HandshakeDigest() throws NoSuchAlgorithmException {
        messageDigest = MessageDigest.getInstance("SHA-256");
    }

    /*
     * Update digest with input data
     */
    public void update(byte[] input) {
        this.input = input;
        messageDigest.update(input);

    }

    /*
     * Compute final digest
     */
    public byte[] digest() {
       return  messageDigest.digest();
    }
};
