package net.felsing.cryptfetchspring;

import net.felsing.cryptfetchspring.crypto.certs.CA;
import net.felsing.cryptfetchspring.crypto.certs.CmsSign;
import net.felsing.cryptfetchspring.crypto.certs.Signer;
import net.felsing.cryptfetchspring.crypto.config.Configuration;
import net.felsing.cryptfetchspring.crypto.util.PemUtils;
import net.felsing.cryptfetchspring.models.ErrorModel;
import net.felsing.cryptfetchspring.models.RenewModel;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.security.cert.X509Certificate;


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
    public byte[] doPayload (CmsSign.Result plainTextContent)
            throws IOException {
        long errNoCounter = 100000; // create unique error numbers on each step

        PKCS10CertificationRequest pkcs10Req = PemUtils.convertPemToPKCS10CertificationRequest(plainTextContent.getContent());

        errNoCounter++;
        X509Certificate x509Certificate = plainTextContent.getCertificates().get(0);
        String subject;
        try {
            x509Certificate.checkValidity();
            subject = x509Certificate.getSubjectDN().getName();
        } catch (Exception e) {
            logger.warn("renew failed: {} ({})", errNoCounter, e.getMessage());
            ErrorModel errorModel = new ErrorModel(String.format("renew failed: %d", errNoCounter));
            return errorModel.serialize();
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
            logger.warn(String.format("renew failed: %s (%s)", errNoCounter, e));
            ErrorModel errorModel = new ErrorModel(String.format("renew failed: %s (%s)", errNoCounter, e));
            return errorModel.serialize();
        }

        RenewModel renewResult = new RenewModel(signedClientCert);

        return renewResult.serialize();
    }

} // class
