import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import java.lang.*;
import java.io.InputStream;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;

import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateFactory;
import java.io.ByteArrayInputStream;

/*
 * HandshakeCertificate class represents X509 certificates exchanged
 * during initial handshake
 */
public class HandshakeCertificate {
    X509Certificate x509Certificate;

    /*
     * Constructor to create a certificate from data read on an input stream.
     * The data is DER-encoded, in binary or Base64 encoding (PEM format).
     */
    HandshakeCertificate(InputStream instream) throws CertificateException {
        CertificateFactory certificate_factory=CertificateFactory.getInstance("X.509");
        x509Certificate=(X509Certificate)certificate_factory.generateCertificate(instream);
    }

    /*
     * Constructor to create a certificate from its encoded representation
     * given as a byte array
     */
    HandshakeCertificate(byte[] certbytes) throws CertificateException {
        CertificateFactory certificate_factory=CertificateFactory.getInstance("X.509");
        ByteArrayInputStream instream=new ByteArrayInputStream(certbytes);
        x509Certificate = (X509Certificate)certificate_factory.generateCertificate(instream);
    }

    /*
     * Return the encoded representation of certificate as a byte array
     */
    public byte[] getBytes() throws CertificateEncodingException {
        return x509Certificate.getEncoded();
    }

    /*
     * Return the X509 certificate
     */
    public X509Certificate getCertificate() {
        return x509Certificate;
    }

    /*
     * Cryptographically validate a certificate.
     * Throw relevant exception if validation fails.
     */
    public void verify(HandshakeCertificate cacert) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, NoSuchProviderException {
        x509Certificate.verify(cacert.getCertificate().getPublicKey());
    }

    /*
     * Return CN (Common Name) of subject
     */
    public String getCN() {
        String info = x509Certificate.getSubjectX500Principal().getName();
        try{
            //learned from stackoverflow; use ldap construct a sql and search in Rdn, use .stream().filter() search for key words.
            return new LdapName(info).getRdns().stream().filter(i -> i.getType().equalsIgnoreCase("CN")).findFirst().get().getValue().toString();
        } catch (InvalidNameException e) {
            throw new RuntimeException(e);
        }


    }

    /*
     * return email address of subject
     */
    public String getEmail() {
        String info = x509Certificate.getSubjectDN().getName();
        try{
            return new LdapName(info).getRdns().stream().filter(i -> i.getType().equalsIgnoreCase("EMAILADDRESS")).findFirst().get().getValue().toString();
        } catch (InvalidNameException e) {
            throw new RuntimeException(e);
        }

    }
}
