package net.felsing.cryptfetchspring.login;

import com.fasterxml.jackson.databind.ObjectMapper;
import net.felsing.cryptfetchspring.CryptInit;
import net.felsing.cryptfetchspring.crypto.certs.EncryptAndDecrypt;
import net.felsing.cryptfetchspring.crypto.certs.ServerCertificate;
import net.felsing.cryptfetchspring.crypto.certs.Signer;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.operator.OperatorCreationException;

import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;
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


    @Override
    public Map login(String cms) {
        HashMap<String, Object> result = new HashMap<>();

        ServerCertificate serverCertificate = CryptInit.getServerCertificate();
        KeyPair keyPair = serverCertificate.getServerKeyPair();
        X509Certificate certificate = serverCertificate.getServerCertificate();

        EncryptAndDecrypt encryptAndDecrypt = new EncryptAndDecrypt();
        try {
            byte[] decrypted = encryptAndDecrypt.decrypt(keyPair.getPrivate(), certificate, cms.getBytes());
            ObjectMapper objectMapper = new ObjectMapper();
            Map unparsedCredentials = objectMapper.readValue(decrypted, Map.class);
            HashMap<String, String> credentials = new HashMap<>(unparsedCredentials);

            return execLogin(credentials);
        } catch (IOException | CMSException e) {
            logger.error(e);
            result.put("authenticated", false);
        }
        return result;
    }


    private Map<String, Object> execLogin(Map<String, String> credentials) {
        HashMap<String, Object> result = new HashMap<>();
        String username = credentials.get("username");
        if (validateCredentials(username, credentials.get("password"))) {
            result.put("authenticated", true);
            try {
                result.put("certificate", sign("CN=" + username, credentials.get("csr")));
            } catch (Exception e) {
                logger.error("Cannot sign certificate");
                result.put("authenticated", false);
            }
        } else {
            result.put("authenticated", false);
        }
        return result;
    }


    private boolean validateCredentials(String username, String password) {
        return true;
    }


    private String sign(String subject, String csr) throws IOException, CertificateException, OperatorCreationException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
        Signer signer = new Signer();
        signer.setValidTo(1);
        signer.setSubject(subject);
        return signer.signClient(csr, CryptInit.getCa().getCaPrivateKeyPEM(), CryptInit.getCa().getCaCertificatePEM());
    }


    private HashMap<String, String> validate (Map hostileData) {
        HashMap<String, String> cleanedData = new HashMap<>();
        hostileData.forEach((k, v) -> {
            if (k instanceof String && v instanceof String) {
                if (validate(k, v)) {
                    cleanedData.put((String) k, (String) v);
                }
            }
        });

        return cleanedData;
    }


    private boolean validate (Object k, Object v) {
        String keyPattern = "^a-z{2,32}$";
        String valuePattern = "^(a-z|A-Z|0.9){2,32}$";
        String passwordPattern = "^(a-z|A-Z|0.9){2,1024}$";
        boolean ok = false;
        if (k instanceof String && v instanceof String) {
            String pattern = valuePattern;
            if (k.equals("password")) { pattern = passwordPattern; }
            if (((String) k).matches(keyPattern) && ((String) v).matches(pattern)) {
                ok = true;
            }
        }
        return ok;
    }

} // class
