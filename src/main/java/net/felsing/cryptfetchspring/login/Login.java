package net.felsing.cryptfetchspring.login;

import com.fasterxml.jackson.databind.ObjectMapper;
import net.felsing.cryptfetchspring.CryptInit;
import net.felsing.cryptfetchspring.crypto.certs.EncryptAndDecrypt;
import net.felsing.cryptfetchspring.crypto.certs.ServerCertificate;
import net.felsing.cryptfetchspring.crypto.certs.Signer;
import net.felsing.cryptfetchspring.crypto.config.Configuration;
import net.felsing.cryptfetchspring.crypto.util.CheckedCast;
import net.felsing.cryptfetchspring.crypto.util.PemUtils;
import org.slf4j.LoggerFactory;
import org.slf4j.Logger;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.operator.OperatorCreationException;
import java.io.IOException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.Map;


public class Login implements LoginIntf {
    private static final Logger logger = LoggerFactory.getLogger(Login.class);

    private final Configuration config;

    private static final String S_FALSE = Boolean.toString(false);
    private static final String S_TRUE = Boolean.toString(true);
    private static final String AUTHENTICATED = "authenticated";
    private static final String USERNAME = "username";
    private static final String PASSWORD = "password";


    public Login () {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        config = new Configuration();
    }


    @Override
    public HashMap<String, String> login(String cms) {
        HashMap<String, String> result = new HashMap<>();

        ServerCertificate serverCertificate = CryptInit.getServerCertificate();
        KeyPair keyPair = serverCertificate.getServerKeyPair();
        X509Certificate certificate = serverCertificate.getServerCertificate();

        EncryptAndDecrypt encryptAndDecrypt = new EncryptAndDecrypt();
        try {
            byte[] decrypted = encryptAndDecrypt.decrypt(keyPair.getPrivate(), certificate, cms);
            ObjectMapper objectMapper = new ObjectMapper();

            // credentials contains unvalidated, client provided data which may
            // contain malicious content. First we do a type safe cast
            HashMap<String, String> credentials = new HashMap<>(
                    CheckedCast.castToMapOf(
                        String.class,
                        String.class,
                        objectMapper.readValue(decrypted, HashMap.class)
                    )
            );

            return execLogin(credentials);

        } catch (IOException | CMSException e) {
            logger.error(e.getMessage());
            result.put(AUTHENTICATED, S_FALSE);
        }
        return result;
    }


    private HashMap<String, String> execLogin(Map<String, String> credentials) {
        // credentials contains unvalidated, client provided data which may
        // contain malicious content. Do not use w/o validation!

        HashMap<String, String> result = new HashMap<>();

        String username;
        if (validate(USERNAME, credentials.get(USERNAME))) {
            username = credentials.get(USERNAME);
        } else {
            logger.warn("username validation failed");
            result.put(AUTHENTICATED, S_FALSE);
            return result;
        }

        String password;
        if (validate(PASSWORD, credentials.get(PASSWORD))) {
            password = credentials.get(PASSWORD);
        } else {
            logger.warn("password validation failed");
            result.put(AUTHENTICATED, S_FALSE);
            return result;
        }

        String pkcs10;
        if (validate("csr", credentials.get("csr"))) {
            pkcs10 = credentials.get("csr");
        } else {
            logger.warn("csr validation failed");
            result.put(AUTHENTICATED, S_FALSE);
            return result;
        }

        if (validateCredentials(username, password)) {
            try {
                result.put("certificate", sign("CN=" + username, pkcs10));
                result.put(AUTHENTICATED, S_TRUE);
            } catch (Exception e) {
                logger.error("Cannot sign certificate");
                result.put(AUTHENTICATED, S_FALSE);
            }
        } else {
            result.put(AUTHENTICATED, S_FALSE);
        }
        return result;
    }


    private boolean validateCredentials(String username, String password) {

        // Test: Validates id username and password are not empty
        // In production environments this should ask a database LDAP or whatever
        return (!username.isEmpty() && !password.isEmpty());
    }


    private String sign(String subject, String csr)
            throws IOException, CertificateException, OperatorCreationException,
            NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
        Signer signer = new Signer();
        int days = Integer.parseInt(config.getConfig().getProperty("certificate.days"));
        signer.setValidTo(days);
        signer.setSubject(subject);
        return signer.signClient(csr, CryptInit.getCa().getCaPrivateKeyPEM(), CryptInit.getCa().getCaCertificatePEM());
    }


    private boolean validatePkcs10 (String pkcs10pem) {
        boolean ok = false;
        try {
            PemUtils.convertPemToPKCS10CertificationRequest(pkcs10pem);
            ok = true;
        } catch (IOException e) {
            logger.warn("CSR validation failed");
        }

        return ok;
    }


    private boolean validate(Object k, Object v) {
        String keyPattern = "^[a-z]{2,32}$";
        String valuePattern = "^[a-zA-Z0-9]{2,32}$";
        String passwordPattern = "^[a-zA-Z0-9\\[=-_\\]^]{6,1024}$";

        boolean ok = false;

        String key;
        if (k instanceof String && ((String) k).matches(keyPattern)) {
            key = (String) k;
        } else {
            logger.warn("Key validation failed");
            return false;
        }

        String value;
        if (v instanceof String) {
            value = (String) v;
        } else {
            logger.warn("Value validation failed");
            return false;
        }

        String pattern = valuePattern;
        if (key.equals(PASSWORD)) {
            pattern = passwordPattern;
        }
        if (key.equals("csr")) {
            ok = validatePkcs10(value);
        } else {
            if (value.matches(pattern)) {
                ok = true;
            } else {
                logger.warn("Value validation failed");
            }
        }

        return ok;
    }

} // class
