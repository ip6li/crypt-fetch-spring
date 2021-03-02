package net.felsing.cryptfetchspring.crypto.util;


import net.felsing.cryptfetchspring.crypto.config.Constants;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;


/****************************************************************************************************************
 * Utility class which provides useful tools to convert certificates and keys in PEM format
 * from and to Java classes
 ***************************************************************************************************************/
public final class PemUtils {
    private static final Logger logger = LoggerFactory.getLogger(PemUtils.class);

    private PemUtils () {}

    /**
     * Utilities to encode different X.509/Key objects to PEM
     *
     * @param pem                   pem encoded data
     * @return                      DER encoded data
     */
    public static byte[] parseDERfromPEM(byte[] pem) {
        String begin = "-----BEGIN.*?-----";
        String end = "-----END.*-----";

        String data = new String(pem, StandardCharsets.UTF_8)
                .replaceFirst(begin, "")
                .replaceFirst(end, "")
                .replaceAll("\\s", "");

        return Base64.getDecoder().decode(data);
    }


    public static String encodeObjectToPEM (X509Certificate crt) throws CertificateEncodingException, IOException {

        return internalEncodeObjectToPEM(crt);
    }


    public static String encodeObjectToPEM (Certificate crt) throws CertificateEncodingException, IOException {

        return internalEncodeObjectToPEM(crt);
    }


    public static String encodeObjectToPEM (CMSEnvelopedData cms) throws CertificateEncodingException, IOException {

        return internalEncodeObjectToPEM(cms);
    }


    public static String encodeObjectToPEM (CMSSignedData cms) throws CertificateEncodingException, IOException {

        return internalEncodeObjectToPEM(cms);
    }


    public static String encodeObjectToPEM (PKCS10CertificationRequest pkcs10) throws CertificateEncodingException, IOException {

        return internalEncodeObjectToPEM(pkcs10);
    }


    public static String encodeObjectToPEM (PrivateKey key) throws CertificateEncodingException, IOException {

        return internalEncodeObjectToPEM(key);
    }


    public static String encodeObjectToPEM (PublicKey key) throws CertificateEncodingException, IOException {

        return internalEncodeObjectToPEM(key);
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
    private static String internalEncodeObjectToPEM(Object o) throws CertificateEncodingException, IOException {
        StringWriter sw = new StringWriter();
        final String LINE64 = "(.{64})";

        if (o instanceof X509Certificate) {
            X509Certificate crt = (X509Certificate) o;
            sw.write(Constants.CRT_BEGIN + "\n");
            sw.write(Base64.getEncoder().encodeToString(
                    crt.getEncoded()).replaceAll(LINE64, "$1\n")
            );
            sw.write("\n" + Constants.CRT_END + "\n");
        } else if (o instanceof Certificate) {
            Certificate cert = (Certificate) o;
            sw.write(Constants.CRT_BEGIN + "\n");
            sw.write(Base64.getEncoder().encodeToString(
                    cert.getEncoded()).replaceAll(LINE64, "$1\n")
            );
            sw.write("\n" + Constants.CRT_END);
        } else if (o instanceof CMSEnvelopedData) {
            CMSEnvelopedData cms = (CMSEnvelopedData) o;
            sw.write(Constants.CMS_BEGIN + "\n");
            sw.write(Base64.getEncoder().encodeToString(
                    cms.getEncoded()).replaceAll(LINE64, "$1\n")
            );
            sw.write("\n" + Constants.CMS_END);
        } else if (o instanceof CMSSignedData) {
            CMSSignedData cms = (CMSSignedData) o;
            sw.write(Constants.CMS_BEGIN + "\n");
            sw.write(Base64.getEncoder().encodeToString(
                    cms.getEncoded()).replaceAll(LINE64, "$1\n")
            );
            sw.write("\n" + Constants.CMS_END);
        } else if (o instanceof PKCS10CertificationRequest) {
            PKCS10CertificationRequest csr = (PKCS10CertificationRequest) o;
            sw.write(Constants.CSR_BEGIN + "\n");
            sw.write(Base64.getEncoder().encodeToString(
                    csr.getEncoded()).replaceAll(LINE64, "$1\n")
            );
            sw.write("\n" + Constants.CSR_END);
        } else if (o instanceof PrivateKey) {
            PrivateKey key = (PrivateKey) o;
            sw.write(Constants.PRIVATE_KEY_BEGIN + "\n");
            sw.write(Base64.getEncoder().encodeToString(
                    key.getEncoded()).replaceAll(LINE64, "$1\n")
            );
            sw.write("\n" + Constants.PRIVATE_KEY_END);
        } else if (o instanceof PublicKey) {
            PublicKey key = (PublicKey) o;
            sw.write(Constants.PUBLIC_KEY_BEGIN + "\n");
            sw.write(Base64.getEncoder().encodeToString(
                    key.getEncoded()).replaceAll(LINE64, "$1\n")
            );
            sw.write("\n" + Constants.PUBLIC_KEY_END);
        } else {
            if (logger.isErrorEnabled()) {
                logger.error(String.format("Cannot convert class '%s' to PEM", o.getClass().getName()));
            }
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


    /**
     * Parses PEM encoded X.509 certificate and returns X509Certificate instance.
     *
     * @param pem               PEM encoded X.509 certificate
     * @return                  X509Certificate
     */
    public static X509Certificate getCertificateFromPem(String pem)
            throws CertificateException {
        InputStream pemstream = new ByteArrayInputStream(pem.getBytes(StandardCharsets.UTF_8));
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(pemstream);
    }


    /**
     * Parses PEM encoded private key and returns RSAPrivateKey instance.
     *
     * @param pem               PEM encoded private key
     * @return                  RSAPrivateKey
     */
    private static PrivateKey getRsaPrivateKeyFromPem(String pem)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(parseDERfromPEM(pem.getBytes()));
            return kf.generatePrivate(keySpec);
    }

    private static PrivateKey getEcPrivateKeyFromPem(String pem)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
            KeyFactory kf = KeyFactory.getInstance("EC");
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(parseDERfromPEM(pem.getBytes()));
            return kf.generatePrivate(keySpec);
    }

    public static PrivateKey getPrivateKeyFromPem(String pem)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        try {
            return getRsaPrivateKeyFromPem(pem);
        } catch (InvalidKeySpecException e) {
            logger.trace(String.format("getPrivateKeyFromPem (RSA): %s", e.getMessage()));
        }

        try {
            return getEcPrivateKeyFromPem(pem);
        } catch (InvalidKeySpecException e) {
            logger.debug(String.format("getPrivateKeyFromPem (EC): %s", e.getMessage()));
            throw new InvalidKeySpecException(e);
        }
    }

    /**
     * Parses PEM encoded private key/certificate and
     * returns KeyPair instance.
     *
     * @param pemPrivateKey     PEM encoded private key
     * @param pemCert           PEM encoded X.509 certificate
     * @return                  KeyPair
     */
    public static KeyPair getKeyPair (String pemPrivateKey, String pemCert)
            throws CertificateException, NoSuchAlgorithmException, InvalidKeySpecException {
        X509Certificate x509cert = getCertificateFromPem(pemCert);
        PublicKey publicKey = x509cert.getPublicKey();
        PrivateKey privKey = getPrivateKeyFromPem(pemPrivateKey);

        return new KeyPair(publicKey, privKey);
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


    /**
     * Converts PEM encoded PKCS#10 request to PKCS10CertificationRequest
     *
     * @param pem               PEM encoded PKCS#10 request
     * @return                  PKCS10CertificationRequest or Exception
     */
    public static PKCS10CertificationRequest convertPemToPKCS10CertificationRequest(String pem)
            throws IOException {

        return convertPemToPKCS10CertificationRequest (pem.getBytes(StandardCharsets.UTF_8));
    }


    /**
     * Converts PEM encoded PKCS#10 request to PKCS10CertificationRequest
     *
     * @param pem               PEM encoded PKCS#10 request
     * @return                  PKCS10CertificationRequest or Exception
     */
    public static PKCS10CertificationRequest convertPemToPKCS10CertificationRequest(byte[] pem)
            throws IOException {
        PKCS10CertificationRequest csr = null;
        ByteArrayInputStream pemStream;
        pemStream = new ByteArrayInputStream(pem);

        try(Reader pemReader = new BufferedReader(new InputStreamReader(pemStream))) {
            PEMParser pemParser = new PEMParser(pemReader);
            Object parsedObj = pemParser.readObject();

            if (parsedObj instanceof PKCS10CertificationRequest) {
                csr = (PKCS10CertificationRequest) parsedObj;
            }

            return csr;
        }
    }

} // class
