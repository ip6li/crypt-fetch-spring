package net.felsing.cryptfetchspring;

import net.felsing.cryptfetchspring.crypto.certs.*;
import net.felsing.cryptfetchspring.crypto.config.Configuration;
import net.felsing.cryptfetchspring.crypto.util.JsonUtils;
import net.felsing.cryptfetchspring.crypto.util.PemUtils;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
import org.slf4j.LoggerFactory;
import org.slf4j.Logger;


public class PayloadRenew implements PayloadIntf {
    private static final Logger logger = LoggerFactory.getLogger(PayloadRenew.class);

    private final CA ca;
    private final Configuration config;


    private PayloadRenew() {
        ca = CryptInit.getCa();
        config = new Configuration();
    }


    public static PayloadRenew getInstance() {

        return new PayloadRenew();
    }


    @Override
    public Map<String,String> doPayload (CmsSign.Result plainTextContent)
            throws Exception {
        long errNoCounter = 100000; // create unique error numbers on each step

        String pkcs10ReqPEM = new String(plainTextContent.getContent(), StandardCharsets.UTF_8);
        PKCS10CertificationRequest pkcs10Req = PemUtils.convertPemToPKCS10CertificationRequest(pkcs10ReqPEM);

        errNoCounter++;
        X509Certificate x509Certificate = plainTextContent.getCertificates().get(0);
        String subject;
        try {
            x509Certificate.checkValidity();
            subject = x509Certificate.getSubjectDN().getName();
        } catch (Exception e) {
            logger.warn("renew failed: {} ({})", errNoCounter, e.getMessage());
            return JsonUtils.genError("renew failed: " + errNoCounter);
        }

        errNoCounter++;
        String signedClientCert;
        try {
            Signer signer = new Signer();
            int days = Integer.parseInt(config.getConfig().getProperty("certificate.days"));
            signer.setSubject(subject);
            signer.setValidTo(days);
            signedClientCert = signer.signClient(
                    PemUtils.encodeObjectToPEM(pkcs10Req),
                    ca.getCaPrivateKeyPEM(),
                    ca.getCaCertificatePEM()
            );
        } catch (Exception e) {
            logger.warn("renew failed: {} ({})", errNoCounter, e);
            return JsonUtils.genError("renew failed: " + errNoCounter);
        }

        HashMap<String, String> renewResult = new HashMap<>();
        renewResult.put("certificate", signedClientCert);

        return renewResult;
    }

} // class
