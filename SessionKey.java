import javax.crypto.SecretKey;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;

/*
 * Skeleton code for class SessionKey
 */

class SessionKey {
    public SecretKey secretkey;

    /*
     * Constructor to create a secret key of a given length
     */
    public SessionKey(Integer length) throws NoSuchAlgorithmException {
        //Creating a KeyGenerator object
        KeyGenerator keygenerator = KeyGenerator.getInstance("AES");
        //Initializing the KeyGenerator
        keygenerator.init(length);
        //Generating a key
        secretkey = keygenerator.generateKey();
    }

    /*
     * Constructor to create a secret key from key material
     * given as a byte array
     */
    public SessionKey(byte[] keybytes) {
        //Creating a KeyGenerator object according to keybytes
        secretkey = new SecretKeySpec(keybytes,"AES");
    }

    /*
     * Return the secret key
     */
    public SecretKey getSecretKey() {
        return secretkey;
    }

    /*
     * Return the secret key encoded as a byte array
     */
    public byte[] getKeyBytes() {
        return secretkey.getEncoded();
    }
}

