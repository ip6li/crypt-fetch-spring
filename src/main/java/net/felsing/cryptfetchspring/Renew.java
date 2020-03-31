package net.felsing.cryptfetchspring;

import net.felsing.cryptfetchspring.crypto.certs.*;
import net.felsing.cryptfetchspring.crypto.config.Configuration;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;


public class Renew {
    private static Logger logger = LogManager.getLogger(Renew.class);

    private CA ca;
    private ServerCertificate serverCertificate;
    private Configuration config;


    private Renew () {
        ca = CryptInit.getCa();
        serverCertificate = CryptInit.getServerCertificate();
        config = new Configuration();
    }


    public static Renew getInstance() {

        return new Renew();
    }


    public Map<String,String> renew (String cmsRequest) {
        byte[] cmsSignedMsg;
        long errNoCounter = 100000; // create unique error numbers on each step

        errNoCounter++;
        try {
            cmsSignedMsg = decrypt(cmsRequest);
        } catch (Exception e) {
            logger.warn("renew failed: {} ({})", errNoCounter, e.getMessage());
            return genError("renew failed: " + errNoCounter);
        }

        errNoCounter++;
        CmsSign.Result validationResult;
        try {
            validationResult = validate(cmsSignedMsg);
        } catch (Exception e) {
            logger.warn("renew failed: {} ({})", errNoCounter, e.getMessage());
            return genError("renew failed: " + errNoCounter);
        }

        errNoCounter++;
        X509Certificate x509Certificate = validationResult.getCertificates().get(0);
        String subjectDN = x509Certificate.getSubjectDN().getName();
        String algorithm = x509Certificate.getPublicKey().getAlgorithm();
        try {
            x509Certificate.checkValidity();
        } catch (Exception e) {
            logger.warn("renew failed: {} ({})", errNoCounter, e.getMessage());
            return genError("renew failed: " + errNoCounter);
        }

        errNoCounter++;
        Certificates.KeyType keyType;
        if (algorithm.matches("^RSA.*$")) {
            keyType = Certificates.KeyType.RSA;
        } else {
            logger.warn("renew: not supported algorithm: {}", errNoCounter);
            return genError("renew failed: " + errNoCounter);
        }

        errNoCounter++;
        String pkcs10CertificationRequest;
        try {
            Csr csr = new Csr();
            csr.createCsr(keyType, subjectDN);
            pkcs10CertificationRequest = csr.getCsrPEM();
        } catch (Exception e) {
            logger.warn("renew failed: {} ({})", errNoCounter, e.getMessage());
            return genError("renew failed: " + errNoCounter);
        }

        errNoCounter++;
        String signedClientCert;
        try {
            Signer signer = new Signer();
            int days = Integer.parseInt(config.getConfig().getProperty("certificate.days"));
            signer.setValidTo(days);
            signedClientCert = signer.signClient(
                    pkcs10CertificationRequest,
                    ca.getCaPrivateKeyPEM(),
                    ca.getCaPrivateKeyPEM()
            );
        } catch (Exception e) {
            logger.warn("renew failed: {} ({})", errNoCounter, e.getMessage());
            return genError("renew failed: " + errNoCounter);
        }

        HashMap<String, String> renewResult = new HashMap<>();
        renewResult.put("certificate", signedClientCert);

        return renewResult;
    }


    private HashMap<String, String> genError (String msg) {
        HashMap<String,String> errMsg = new HashMap<>();
        errMsg.put("error", msg);
        return errMsg;
    }


    private byte[] decrypt (String cmsEncryptedMsg)
            throws IOException, CMSException {
        EncryptAndDecrypt encryptAndDecrypt = new EncryptAndDecrypt();
        return encryptAndDecrypt.decrypt(
                serverCertificate.getServerKeyPair().getPrivate(),
                serverCertificate.getServerCertificate(),
                cmsEncryptedMsg.getBytes()
        );
    }


    private CmsSign.Result validate (byte[] cmsSignedMessage)
            throws CMSException {
        CmsSign cms = new CmsSign();
        CmsSign.Result result = cms.verifyCmsSignature(
                new CMSSignedData(cmsSignedMessage),
                ca.getCaX509Certificate()
        );
        if (!result.isVerifyOk()) {
            throw new CMSException("Validation failed while renew");
        }

        return result;
    }

} // class
