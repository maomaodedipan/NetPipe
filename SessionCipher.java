import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;

public class SessionCipher {
    public SessionKey key;
    public byte[] ivbytes;
    public Cipher cipher;

    /*
     * Constructor to create a SessionCipher from a SessionKey. The IV is
     * created automatically.
     */
    public SessionCipher(SessionKey key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException {
        this.key = key;
        this.cipher = Cipher.getInstance("AES/CTR/NoPadding");
        SecureRandom random = new SecureRandom();
        byte [] ivbytes = new byte[cipher.getBlockSize()];
        random.nextBytes(ivbytes);
        this.ivbytes = ivbytes;
        cipher.init(Cipher.ENCRYPT_MODE, key.getSecretKey(),new IvParameterSpec(ivbytes));
    }

    /*
     * Constructor to create a SessionCipher from a SessionKey and an IV,
     * given as a byte array.
     */

    public SessionCipher(SessionKey key, byte[] ivbytes, boolean mode) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException {
        this.key = key;
        this.ivbytes = ivbytes;
        cipher = Cipher.getInstance("AES/CTR/NoPadding");
        if(mode == false){
        cipher.init(Cipher.DECRYPT_MODE, key.getSecretKey(), new IvParameterSpec(ivbytes));
        }
        else {
            cipher.init(Cipher.ENCRYPT_MODE, key.getSecretKey(), new IvParameterSpec(ivbytes));
        }

    }

    /*
     * Return the SessionKey
     */
    public SessionKey getSessionKey() {
        return this.key;
    }

    /*
     * Return the IV as a byte array
     */
    public byte[] getIVBytes() {
        return this.ivbytes;
    }

    /*
     * Attach OutputStream to which encrypted data will be written.
     * Return result as a CipherOutputStream instance.
     */
    CipherOutputStream openEncryptedOutputStream(OutputStream os){
        return new CipherOutputStream(os,cipher);
    }

    /*
     * Attach InputStream from which decrypted data will be read.
     * Return result as a CipherInputStream instance.
     */

    CipherInputStream openDecryptedInputStream(InputStream inputstream){
        return new CipherInputStream(inputstream,cipher);
    }
}
