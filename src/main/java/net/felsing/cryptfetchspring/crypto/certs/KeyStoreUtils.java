package net.felsing.cryptfetchspring.crypto.certs;

import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Enumeration;
import org.slf4j.LoggerFactory;
import org.slf4j.Logger;


public final class KeyStoreUtils {
    private static final Logger logger = LoggerFactory.getLogger(KeyStoreUtils.class);
    private enum KS_MODE {KEYPAIR, CERTIFICATE}

    public static KeyStore loadKeystore(String keystoreFile, String keystorePassword) throws
            KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        InputStream readStream = new FileInputStream(keystoreFile);
        keyStore.load(readStream, keystorePassword.toCharArray());
        readStream.close();

        return keyStore;
    }


    public static X509Certificate getCertificateFromKeystore(KeyStore keyStore, String keystorePassword)
            throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException {

        return (X509Certificate) getKeyPairOrCertificate(KS_MODE.CERTIFICATE, keyStore, keystorePassword);
    }


    public static KeyPair getKeypairFromKeystore(KeyStore keyStore, String keystorePassword)
            throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException {

        return (KeyPair) getKeyPairOrCertificate(KS_MODE.KEYPAIR, keyStore, keystorePassword);
    }


    public static void saveToKeystore (String alias, KeyPair keyPair, X509Certificate x509Certificate,
                                       String keyStoreFile, String password)
            throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        X509Certificate[] x509CertificateList = new X509Certificate[1];
        x509CertificateList[0]=x509Certificate;
        keyStore.load(null, null);

        KeyStore.Entry entry = new KeyStore.PrivateKeyEntry(keyPair.getPrivate(), x509CertificateList);
        keyStore.setEntry(alias, entry, new KeyStore.PasswordProtection(password.toCharArray()));

        OutputStream os = new FileOutputStream(keyStoreFile);
        keyStore.store(os, password.toCharArray());
        os.close();
    }


    private static Object getKeyPairOrCertificate(KS_MODE ksMode, KeyStore keyStore, String keystorePassword)
            throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException {
        PrivateKey privateKey = null;
        PublicKey publicKey = null;
        X509Certificate x509Certificate = null;

        Enumeration<String> e = keyStore.aliases();
        if (e.hasMoreElements()) {
            String alias = e.nextElement();
            Key key = keyStore.getKey(alias, keystorePassword.toCharArray());
            x509Certificate = (X509Certificate) keyStore.getCertificate(alias);
            publicKey = x509Certificate.getPublicKey();

            // first, try to generate a RSA key
            try {
                KeyFactory factory = KeyFactory.getInstance("RSA");
                privateKey = factory.generatePrivate(
                        new PKCS8EncodedKeySpec(key.getEncoded())
                );
            } catch (Exception ivKey) {
                privateKey = null;
            }

            // if RSA failed, try to generate an EC key
            if (privateKey == null) {
                try {
                    KeyFactory factory = KeyFactory.getInstance("EC");
                    privateKey = factory.generatePrivate(
                            new PKCS8EncodedKeySpec(key.getEncoded())
                    );
                } catch (Exception ivEcKey) {
                    logger.warn(ivEcKey.getMessage());
                    throw new UnrecoverableKeyException("Certificate is neither RSA nor EC");
                }
            }
        }

        if ((privateKey == null) || (publicKey == null)) {
            throw new UnrecoverableKeyException("Cannot recover keystore");
        }

        switch (ksMode) {
            case KEYPAIR:
                return new KeyPair(publicKey, privateKey);
            case CERTIFICATE:
                return x509Certificate;
        }

        throw new UnrecoverableKeyException("invalid keystore mode (strange: Should never happen if enum KS_MODE was used)");
    }

} // class
