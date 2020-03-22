package net.felsing.cryptfetchspring.crypto.util;

import net.felsing.cryptfetchspring.crypto.certs.Csr;
import net.felsing.cryptfetchspring.crypto.config.Constants;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.security.PublicKey;
import java.util.Base64;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.*;


public final class PemUtils {


    /**
     *
     * @param pem                   pem encoded data
     * @return                      DER encoded data
     */
    public static byte[] parseDERfromPEM(byte[] pem)
            throws ArrayIndexOutOfBoundsException, NullPointerException {
        String begin = "-----BEGIN.*?-----";
        String end = "-----END.*-----";
        String data = new String(pem)
                .replaceFirst(begin, "")
                .replaceFirst(end, "")
                .replaceAll("\\s", "");

        return Base64.getDecoder().decode(data);
    }


    public static String encodeObjectToPEM (X509Certificate crt) throws CertificateEncodingException, IOException {

        return encodeObjectToPEM_(crt);
    }


    public static String encodeObjectToPEM (Certificate crt) throws CertificateEncodingException, IOException {

        return encodeObjectToPEM_(crt);
    }


    public static String encodeObjectToPEM (CMSEnvelopedData cms) throws CertificateEncodingException, IOException {

        return encodeObjectToPEM_(cms);
    }


    public static String encodeObjectToPEM (CMSSignedData cms) throws CertificateEncodingException, IOException {

        return encodeObjectToPEM_(cms);
    }


    public static String encodeObjectToPEM (PKCS10CertificationRequest pkcs10) throws CertificateEncodingException, IOException {

        return encodeObjectToPEM_(pkcs10);
    }


    public static String encodeObjectToPEM (PrivateKey key) throws CertificateEncodingException, IOException {

        return encodeObjectToPEM_(key);
    }


    public static String encodeObjectToPEM (PublicKey key) throws CertificateEncodingException, IOException {

        return encodeObjectToPEM_(key);
    }


    public static String encodeObjectToPEM (Csr csr) throws CertificateEncodingException, IOException {

        return encodeObjectToPEM_(csr.getCsr());
    }


    /**
     * Converts following object types into PEM format:
     *      X509Certificate
     *      Certificate
     *      CMSEnvelopedData
     *      CMSSignedData
     *      PKCS10CertificationRequest
     *      PrivateKey
     *      PublicKey
     *
     * @param o         object of type listed above
     * @return          PEM encoded representation
     * @throws CertificateEncodingException     if o is not an supported type
     */
    private static String encodeObjectToPEM_ (Object o) throws CertificateEncodingException, IOException {
        StringWriter sw = new StringWriter();

        if (o instanceof X509Certificate) {
            X509Certificate crt = (X509Certificate) o;
            sw.write(Constants.CRT_BEGIN + "\n");
            sw.write(Base64.getEncoder().encodeToString(
                    crt.getEncoded()).replaceAll("(.{64})", "$1\n")
            );
            sw.write("\n" + Constants.CRT_END + "\n");
        } else if (o instanceof Certificate) {
            Certificate cert = (Certificate) o;
            sw.write(Constants.CRT_BEGIN + "\n");
            sw.write(Base64.getEncoder().encodeToString(
                    cert.getEncoded()).replaceAll("(.{64})", "$1\n")
            );
            sw.write("\n" + Constants.CRT_END);
        } else if (o instanceof CMSEnvelopedData) {
            CMSEnvelopedData cms = (CMSEnvelopedData) o;
            sw.write(Constants.CMS_BEGIN + "\n");
            sw.write(Base64.getEncoder().encodeToString(
                    cms.getEncoded()).replaceAll("(.{64})", "$1\n")
            );
            sw.write("\n" + Constants.CMS_END);
        } else if (o instanceof CMSSignedData) {
            CMSSignedData cms = (CMSSignedData) o;
            sw.write(Constants.CMS_BEGIN + "\n");
            sw.write(Base64.getEncoder().encodeToString(
                    cms.getEncoded()).replaceAll("(.{64})", "$1\n")
            );
            sw.write("\n" + Constants.CMS_END);
        } else if (o instanceof PKCS10CertificationRequest) {
            PKCS10CertificationRequest csr = (PKCS10CertificationRequest) o;
            sw.write(Constants.CSR_BEGIN + "\n");
            sw.write(Base64.getEncoder().encodeToString(
                    csr.getEncoded()).replaceAll("(.{64})", "$1\n")
            );
            sw.write("\n" + Constants.CSR_END);
        } else if (o instanceof PrivateKey) {
            PrivateKey key = (PrivateKey) o;
            sw.write(Constants.PRIVATE_KEY_BEGIN + "\n");
            sw.write(Base64.getEncoder().encodeToString(
                    key.getEncoded()).replaceAll("(.{64})", "$1\n")
            );
            sw.write("\n" + Constants.PRIVATE_KEY_END);
        } else if (o instanceof PublicKey) {
            PublicKey key = (PublicKey) o;
            sw.write(Constants.PUBLIC_KEY_BEGIN + "\n");
            sw.write(Base64.getEncoder().encodeToString(
                    key.getEncoded()).replaceAll("(.{64})", "$1\n")
            );
            sw.write("\n" + Constants.PUBLIC_KEY_END);
        } else {
            throw new CertificateEncodingException(
                    "unknown Object type " +
                            o.getClass().getName() +
                            ". Supported types are: \n" +
                            "     *      X509Certificate\n" +
                            "     *      Certificate\n" +
                            "     *      CMSEnvelopedData\n" +
                            "     *      CMSSignedData\n" +
                            "     *      PKCS10CertificationRequest\n" +
                            "     *      PrivateKey\n" +
                            "     *      PublicKey"
            );
        }

        String res = sw.toString();
        return res.replaceAll("(?m)^\r?\n", "");
    }


    public static X509Certificate getCertificateFromPem(String pem)
            throws CertificateException {
        InputStream pemstream = new ByteArrayInputStream(pem.getBytes(StandardCharsets.UTF_8));
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(pemstream);
    }


    /**
     * Creates a random string from a list of characters.
     * It is good for creating e.g. certificate serial numbers.
     * Think twice before using it for passwords.
     *
     * @param allowedChars      Array of allowed characters
     * @param len               Length of random word
     * @return                  A random String
     */
    public static String getRandom(byte[] allowedChars, int len) {
        SecureRandom secureRandom = new SecureRandom();
        StringBuilder rnd = new StringBuilder();
        for (int i = 0; i < len; i++) {
            rnd.append(allowedChars[secureRandom.nextInt(allowedChars.length)]);
        }

        return rnd.toString();
    }


} // class
