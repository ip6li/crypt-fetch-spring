package net.felsing.cryptfetchspring;

import net.felsing.cryptfetchspring.crypto.certs.*;
import net.felsing.cryptfetchspring.crypto.util.PemUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSSignedData;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;


@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class TestBasicFunctions {
    private static Logger logger = LogManager.getLogger(TestBasicFunctions.class);

    private static TestLib testLib;


    @BeforeAll
    static void initTests () {
        try {
            testLib = TestLib.getInstance();
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
        HashMap<String, String> clientCert2 = testLib.genClientCertificate("cert2");

        String plainText = "Hello world! Umlaute: äöüÄÖÜß€";
        byte[] bPlainText = plainText.getBytes();

        RSAPrivateKey privateKey2 = PemUtils.getPrivateKeyFromPem(clientCert2.get("privateKey"));
        X509Certificate certificate2 = PemUtils.getCertificateFromPem(clientCert2.get("certificate"));
        EncryptAndDecrypt encryptAndDecrypt = new EncryptAndDecrypt();

        String encryptedText = encryptAndDecrypt.encryptPem(null, null, certificate2, bPlainText);

        byte[] bDecryptedText = encryptAndDecrypt.decrypt(privateKey2, certificate2, encryptedText);

        String decryptedText = new String(bDecryptedText);

        logger.info("[encrypt] plainText: " + plainText);
        logger.info("[encrypt] decryptedText: " + decryptedText);

        assert plainText.equals(decryptedText);
    }

    @Test
    void sign()
            throws Exception {
        HashMap<String, String> clientCert1 = testLib.genClientCertificate("cert1");

        String plainText = "Hello world! Umlaute: äöüÄÖÜß€";
        byte[] bPlainText = plainText.getBytes();

        KeyPair keyPair = PemUtils.getKeyPair(clientCert1.get("privateKey"), clientCert1.get("certificate"));

        Cms cms = new Cms();
        CMSSignedData signedText = cms.signCmsEnveloped(keyPair, PemUtils.getCertificateFromPem(clientCert1.get("certificate")), bPlainText);

        Cms.Result result = cms.verifyCmsSignature(signedText, testLib.getCaCertificate());
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
    void certificate () throws Exception {
        Certificates certificates = new Certificates();
        certificates.createSelfSignedCertificateRSA("CN=mySelfSigned Certificate", 1);
        assert certificates.getX509Certificate() != null;
    }

    @Test
    void generateCsr () throws Exception {
        List<GeneralName> sanList = new LinkedList<>();
        sanList.add(new GeneralName(GeneralName.dNSName, "name.example.com"));
        Csr csr = new Csr();
        csr.createCsr(Certificates.KeyType.RSA, 2048, "CN=my CSR with SAN", sanList);
        logger.info("[generateCsr] " + PemUtils.encodeObjectToPEM(csr.getCsr()));
    }
}
