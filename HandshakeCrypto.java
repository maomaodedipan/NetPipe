import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

public class HandshakeCrypto {

	PublicKey publicKey;
	PrivateKey privateKey;

	/*
	 * Constructor to create an instance for encryption/decryption with a public key.
	 * The public key is given as a X509 certificate.
	 */
	public HandshakeCrypto(HandshakeCertificate handshakeCertificate) {
		publicKey = handshakeCertificate.getCertificate().getPublicKey();
	}

	/*
	 * Constructor to create an instance for encryption/decryption with a private key.
	 * The private key is given as a byte array in PKCS8/DER format.
	 */

	public HandshakeCrypto(byte[] keybytes) throws NoSuchAlgorithmException, InvalidKeySpecException {
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(keybytes);
		privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);

	}

	/*
	 * Decrypt byte array with the key, return result as a byte array
	 */
    public byte[] decrypt(byte[] ciphertext) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance("RSA");
		if(privateKey != null){
		    cipher.init(Cipher.DECRYPT_MODE,privateKey);
		}
		else {
			cipher.init(Cipher.DECRYPT_MODE,publicKey);
		}
		return cipher.doFinal(ciphertext);
    }

	/*
	 * Encrypt byte array with the key, return result as a byte array
	 */
    public byte [] encrypt(byte[] plaintext) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance("RSA");
		if(publicKey != null){
		    cipher.init(Cipher.ENCRYPT_MODE,publicKey);
		}
		else {
			cipher.init(Cipher.ENCRYPT_MODE,privateKey);
		}
		return cipher.doFinal(plaintext);
    }
}
