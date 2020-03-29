package net.felsing.cryptfetchspring;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import net.felsing.cryptfetchspring.crypto.certs.Cms;
import net.felsing.cryptfetchspring.crypto.certs.EncryptAndDecrypt;
import net.felsing.cryptfetchspring.crypto.util.PemUtils;
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
import java.util.HashMap;
import java.util.List;

public class MessageHandler {
    private static Logger logger = LogManager.getLogger(MessageHandler.class);

    private KeyPair serverKeyPair;
    private X509Certificate serverCert;
    private X509Certificate ca;


    private MessageHandler () {}

    private MessageHandler (KeyPair serverKeyPair, X509Certificate serverCert, X509Certificate ca) {
        this.serverKeyPair = serverKeyPair;
        this.serverCert = serverCert;
        this.ca = ca;
    }


    public static MessageHandler getInstance(KeyPair serverKeyPair, X509Certificate serverCert, X509Certificate ca) {

        return new MessageHandler(serverKeyPair, serverCert, ca);
    }


    private String doPlainTextRequest (Cms.Result plainTextRequest)
            throws JsonProcessingException {
        logger.info("[doPlainTextRequest] request: " + new String (plainTextRequest.getContent()));
        HashMap<String,String> plainTextResponse = new HashMap<>();
        plainTextResponse.put("foo", "bar");
        ObjectMapper respMapper = new ObjectMapper();
        return respMapper.writerWithDefaultPrettyPrinter().writeValueAsString(plainTextResponse);
    }


    public String doRequest (String encryptedRequest)
            throws CMSException, OperatorCreationException, CertificateException,
            IOException, InvalidAlgorithmParameterException {
        EncryptAndDecrypt encryptAndDecrypt = new EncryptAndDecrypt();
        Cms cms = new Cms();

        byte[] decrypted = encryptAndDecrypt.decrypt(serverKeyPair.getPrivate(), serverCert, encryptedRequest);
        Cms.Result plainTextAndValidatedReq = cms.verifyCmsSignature(new CMSSignedData(decrypted), ca);
        List<X509Certificate> clientCertificates = plainTextAndValidatedReq.getCertificates();
        X509Certificate clientCert = clientCertificates.get(0);

        String jsonResponse = doPlainTextRequest(plainTextAndValidatedReq);

        CMSSignedData cmsSignedResp = cms.signCmsEnveloped(serverKeyPair, serverCert, jsonResponse.getBytes());

        String encryptedResp = encryptAndDecrypt.encryptPem(
                serverKeyPair.getPrivate(),
                serverCert,
                clientCert,
                cmsSignedResp.getEncoded()
        );

        return encryptedResp;
    }
}
