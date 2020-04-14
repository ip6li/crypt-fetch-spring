package net.felsing.cryptfetchspring;

import net.felsing.cryptfetchspring.crypto.certs.CmsSign;
import net.felsing.cryptfetchspring.crypto.certs.EncryptAndDecrypt;
import net.felsing.cryptfetchspring.crypto.util.JsonUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.operator.OperatorCreationException;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;


public class MessageHandler {
    private static final Logger logger = LogManager.getLogger(MessageHandler.class);

    private final KeyPair serverKeyPair;
    private final X509Certificate serverCert;
    private final X509Certificate ca;


    private MessageHandler (KeyPair serverKeyPair, X509Certificate serverCert, X509Certificate ca) {
        this.serverKeyPair = serverKeyPair;
        this.serverCert = serverCert;
        this.ca = ca;
    }


    public static MessageHandler getInstance(KeyPair serverKeyPair, X509Certificate serverCert, X509Certificate ca) {

        return new MessageHandler(serverKeyPair, serverCert, ca);
    }


    public String doRequest (String encryptedRequest, PayloadIntf callback)
            throws CMSException, OperatorCreationException, CertificateException,
            IOException, InvalidAlgorithmParameterException {
        EncryptAndDecrypt encryptAndDecrypt = new EncryptAndDecrypt();
        CmsSign cmsSign = new CmsSign();

        byte[] decrypted = encryptAndDecrypt.decrypt(serverKeyPair.getPrivate(), serverCert, encryptedRequest);
        CmsSign.Result plainTextAndValidatedReq = cmsSign.verifyCmsSignature(new CMSSignedData(decrypted), ca);
        List<X509Certificate> clientCertificates = plainTextAndValidatedReq.getCertificates();
        X509Certificate clientCert = clientCertificates.get(0);

        String jsonResponse;
        try {
            jsonResponse = JsonUtils.map2json(callback.doPayload(plainTextAndValidatedReq));
        } catch (Exception e) {
            jsonResponse = JsonUtils.map2json(JsonUtils.genError("Cannot process payload"));
            logger.error(e);
        }

        CMSSignedData cmsSignedResp = cmsSign.signCmsEnveloped(serverKeyPair, serverCert, jsonResponse.getBytes());

        return encryptAndDecrypt.encryptPem(
                serverKeyPair.getPrivate(),
                serverCert,
                clientCert,
                cmsSignedResp.getEncoded()
        );
    }
}
