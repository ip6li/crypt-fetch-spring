package net.felsing.cryptfetchspring.login;

import com.fasterxml.jackson.databind.ObjectMapper;
import net.felsing.cryptfetchspring.CryptInit;
import net.felsing.cryptfetchspring.crypto.certs.EncryptAndDecrypt;
import net.felsing.cryptfetchspring.crypto.certs.ServerCertificate;
import net.felsing.cryptfetchspring.crypto.certs.Signer;
import net.felsing.cryptfetchspring.crypto.util.PemUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.operator.OperatorCreationException;
import java.io.IOException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.Map;


public class Login implements loginIntf {
    private static Logger logger = LogManager.getLogger(Login.class);

    final private static String sFalse = Boolean.toString(false);
    final private static String sTrue = Boolean.toString(true);


    @Override
    public HashMap<String, String> login(String cms) {
        HashMap<String, String> result = new HashMap<>();

        ServerCertificate serverCertificate = CryptInit.getServerCertificate();
        KeyPair keyPair = serverCertificate.getServerKeyPair();
        X509Certificate certificate = serverCertificate.getServerCertificate();

        EncryptAndDecrypt encryptAndDecrypt = new EncryptAndDecrypt();
        try {
            byte[] decrypted = encryptAndDecrypt.decrypt(keyPair.getPrivate(), certificate, cms.getBytes());
            ObjectMapper objectMapper = new ObjectMapper();

            // credentials contains unvalidated, client provided data which may
            // contain malicious content.
            HashMap<String, String> credentials = new HashMap<>();
            objectMapper.readValue(decrypted, HashMap.class).forEach((k, v) -> {
                if (k instanceof String && v instanceof String) {
                    credentials.put((String) k, (String) v);
                }
            });
            return execLogin(credentials);

        } catch (IOException | CMSException e) {
            logger.error(e);
            result.put("authenticated", sFalse);
        }
        return result;
    }


    private HashMap<String, String> execLogin(Map<String, String> credentials) {
        // credentials contains unvalidated, client provided data which may
        // contain malicious content. Do not use w/o validation!

        HashMap<String, String> result = new HashMap<>();

        String username;
        if (validate("username", credentials.get("username"))) {
            username = credentials.get("username");
        } else {
            result.put("authenticated", sFalse);
            return result;
        }

        String password;
        if (validate("password", credentials.get("password"))) {
            password = credentials.get("password");
        } else {
            result.put("authenticated", sFalse);
            return result;
        }

        String pkcs10;
        if (validate("csr", credentials.get("csr"))) {
            pkcs10 = credentials.get("csr");
        } else {
            result.put("authenticated", sFalse);
            return result;
        }

        if (validateCredentials(username, password)) {
            try {
                result.put("certificate", sign("CN=" + username, pkcs10));
                result.put("authenticated", sTrue);
            } catch (Exception e) {
                logger.error("Cannot sign certificate");
                result.put("authenticated", sFalse);
            }
        } else {
            result.put("authenticated", sFalse);
        }
        return result;
    }


    private boolean validateCredentials(String username, String password) {

        // Test: Validates id username and password are not empty
        // In production environments this should ask a database LDAP or whatever
        return (!username.isEmpty() && !password.isEmpty());
    }


    private String sign(String subject, String csr) throws IOException, CertificateException, OperatorCreationException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
        Signer signer = new Signer();
        signer.setValidTo(1);
        signer.setSubject(subject);
        return signer.signClient(csr, CryptInit.getCa().getCaPrivateKeyPEM(), CryptInit.getCa().getCaCertificatePEM());
    }


    private boolean validatePkcs10 (String pkcs10pem) {
        boolean ok = false;
        try {
            PemUtils.convertPemToPKCS10CertificationRequest(pkcs10pem);
            ok = true;
        } catch (IOException e) {
            logger.error(e);
        }

        return ok;
    }


    private boolean validate(Object k, Object v) {
        String keyPattern = "^a-z{2,32}$";
        String valuePattern = "^(a-z|A-Z|0-9){2,32}$";
        String passwordPattern = "^(a-z|A-Z|0-9|[-=]){6,1024}$";

        boolean ok = false;

        String key;
        if (k instanceof String && ((String) k).matches(keyPattern)) {
            key = (String) k;
        } else {
            return false;
        }

        String value;
        if (v instanceof String) {
            value = (String) v;
        } else {
            return false;
        }

        String pattern = valuePattern;
        if (key.equals("password")) {
            pattern = passwordPattern;
        }
        if (key.equals("csr")) {
            ok = validatePkcs10(value);
        } else {
            if (value.matches(pattern)) {
                ok = true;
            }
        }

        return ok;
    }

} // class
