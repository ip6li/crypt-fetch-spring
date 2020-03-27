package net.felsing.cryptfetchspring;

import net.felsing.cryptfetchspring.crypto.certs.*;
import net.felsing.cryptfetchspring.crypto.config.Constants;
import net.felsing.cryptfetchspring.crypto.util.PemUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.cms.CMSSignedData;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import java.io.IOException;
import java.security.KeyPair;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.util.HashMap;
import java.util.Map;


@SpringBootTest
class CryptFetchSpringApplicationTests {
    private static Logger logger = LogManager.getLogger(CryptFetchSpringApplicationTests.class);

    private static CA ca;
    private static ServerConfig serverConfig;


    private HashMap<String, String> genClientCertificate (String cn) throws Exception {
        HashMap<String, String> certStore = new HashMap<>();
        Csr request = new Csr();

        String privateKey;
        String csr;
        String certificate;

        request.createCsr(Certificates.KeyType.RSA, 2048, "CN=".concat(cn));
        privateKey = PemUtils.encodeObjectToPEM(request.getKeyPair().getPrivate());
        csr = PemUtils.encodeObjectToPEM(request.getCsr());
        certStore.put("privateKey", privateKey);
        certStore.put("csr", csr);

        Signer signer = new Signer();
        signer.setValidTo(1);

        certificate = signer.signClient(csr, ca.getCaPrivateKeyPEM(), ca.getCaCertificatePEM());
        certStore.put("certificate", certificate);

        return certStore;
    }


    @BeforeAll
    static void initTests () {
        try {
            ca = CryptInit.getInstance("./");
            serverConfig = ServerConfig.getInstance(ca, CryptInit.getServerCertificate(), CryptInit.getSignerCertificate());
        } catch (Exception e) {
            logger.error("BeforeAll failed");
            logger.error(e);
        }
    }

    @Test
    void testServerConfig () {
        ServerConfig localServerConfig = ServerConfig.getServerConfig();
        assert localServerConfig != null;
    }

    @Test
    void encrypt() throws Exception {
        HashMap<String, String> clientCert1 = genClientCertificate("cert1");
        HashMap<String, String> clientCert2 = genClientCertificate("cert2");

        String plainText = "Hello world! Umlaute: äöüÄÖÜß€";
        byte[] bPlainText = plainText.getBytes();

        RSAPrivateKey privateKey1 = PemUtils.getPrivateKeyFromPem(clientCert1.get("privateKey"));
        X509Certificate certificate1 = PemUtils.getCertificateFromPem(clientCert1.get("certificate"));
        RSAPrivateKey privateKey2 = PemUtils.getPrivateKeyFromPem(clientCert2.get("privateKey"));
        X509Certificate certificate2 = PemUtils.getCertificateFromPem(clientCert2.get("certificate"));
        EncryptAndDecrypt encryptAndDecrypt = new EncryptAndDecrypt();
        byte[] encryptedText = encryptAndDecrypt.encrypt(privateKey1, certificate1, certificate2, bPlainText);

        byte[] bDecryptedText = encryptAndDecrypt.decrypt(privateKey2, certificate2, encryptedText);
        String decryptedText = new String(bDecryptedText);

        logger.info("[encrypt] plainText: " + plainText);
        logger.info("[encrypt] decryptedText: " + decryptedText);

        assert plainText.equals(decryptedText);
    }

    @Test
    void sign()
            throws Exception {
        HashMap<String, String> clientCert1 = genClientCertificate("cert1");

        String plainText = "Hello world! Umlaute: äöüÄÖÜß€";
        byte[] bPlainText = plainText.getBytes();

        KeyPair keyPair = PemUtils.getKeyPair(clientCert1.get("privateKey"), clientCert1.get("certificate"));

        Cms cms = new Cms();
        CMSSignedData signedText = cms.signCmsEnveloped(keyPair, PemUtils.getCertificateFromPem(clientCert1.get("certificate")), bPlainText);

        Cms.Result result = cms.verifyCmsSignature(signedText, ca.getCaX509Certificate());
        logger.info("[sign] isVerifyOk:  ".concat(Boolean.toString(result.isVerifyOk())));
        logger.info("[sign] signed Text: ".concat(new String(result.getContent())));
        int[] count = new int[1];
        result.getCertificates().forEach((k) -> {
            try {
                logger.info("[sign] certificate[".concat(Integer.toString(count[0])).concat("]\n").concat(PemUtils.encodeObjectToPEM(k)));
                count[0]=count[0]+1;
            } catch (Exception e) {
                logger.error(e);
            }
        });
        assert result.isVerifyOk();
    }

    @Test
    void contextLoads() {
    }

}
