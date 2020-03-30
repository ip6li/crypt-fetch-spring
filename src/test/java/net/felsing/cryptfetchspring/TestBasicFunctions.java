package net.felsing.cryptfetchspring;

import net.felsing.cryptfetchspring.crypto.certs.*;
import net.felsing.cryptfetchspring.crypto.util.PemUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import java.security.KeyPair;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.util.*;


@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class TestBasicFunctions {
    private static Logger logger = LogManager.getLogger(TestBasicFunctions.class);

    private static TestLib testLib;


    @BeforeAll
    static void initTests() {
        try {
            testLib = TestLib.getInstance();
        } catch (Exception e) {
            logger.error("BeforeAll failed");
            logger.error(e);
        }
    }

    @Test
    void testServerConfig() {
        ServerConfig localServerConfig = ServerConfig.getServerConfig();
        assert localServerConfig != null;
    }

    @Test
    void encrypt() throws Exception {
        HashMap<String, String> clientCert = testLib.genClientCertificate("client Cert for encryption");

        String plainText = "Hello world! Umlaute: äöüÄÖÜß€";
        byte[] bPlainText = plainText.getBytes();

        RSAPrivateKey privateKey = PemUtils.getPrivateKeyFromPem(clientCert.get("privateKey"));
        X509Certificate certificate = PemUtils.getCertificateFromPem(clientCert.get("certificate"));
        EncryptAndDecrypt encryptAndDecrypt = new EncryptAndDecrypt();

        String encryptedText = encryptAndDecrypt.encryptPem(certificate, bPlainText);

        byte[] bDecryptedText = encryptAndDecrypt.decrypt(privateKey, certificate, encryptedText);

        String decryptedText = new String(bDecryptedText);

        logger.info("[encrypt] plainText: " + plainText);
        logger.info("[encrypt] decryptedText: " + decryptedText);

        assert plainText.equals(decryptedText);
    }

    @Test
    void sign()
            throws Exception {
        HashMap<String, String> clientCert = testLib.genClientCertificate("cert1");

        String plainText = "Hello world! Umlaute: äöüÄÖÜß€";
        byte[] bPlainText = plainText.getBytes();

        KeyPair keyPair = PemUtils.getKeyPair(clientCert.get("privateKey"), clientCert.get("certificate"));
        X509Certificate cert = PemUtils.getCertificateFromPem(clientCert.get("certificate"));

        CmsSign cmsSign = new CmsSign();
        CMSSignedData signedText = cmsSign.signCmsEnveloped(keyPair, cert, bPlainText);
        assert PemUtils.encodeObjectToPEM(signedText).length()>0;

        CMSSignedData signedTextDetached = cmsSign.signCmsDetached(keyPair, cert, bPlainText);
        assert signedTextDetached != null;

        CmsSign.Result result = cmsSign.verifyCmsSignature(signedText, TestLib.getCaCertificate());
        logger.info("[sign] isVerifyOk:  ".concat(Boolean.toString(result.isVerifyOk())));
        logger.info("[sign] signed Text: ".concat(new String(result.getContent())));
        int[] count = new int[1];
        result.getCertificates().forEach((k) -> {
            try {
                logger.info("[sign] certificate[".concat(Integer.toString(count[0])).concat("]\n").concat(PemUtils.encodeObjectToPEM(k)));
                count[0] = count[0] + 1;
            } catch (Exception e) {
                logger.error(e);
            }
        });
        assert result.isVerifyOk();
    }


    @Test
    void certificate() throws Exception {
        Certificates certificates = new Certificates();
        certificates.createSelfSignedCertificateRSA("CN=mySelfSigned Certificate", 1);
        assert certificates.getX509Certificate() != null;
    }

    @Test
    void generateCsrWithSAN() throws Exception {
        List<GeneralName> sanList = new LinkedList<>();
        // this SAN will be thrown away by signer
        sanList.add(new GeneralName(GeneralName.dNSName, "name.example.com"));
        Csr csr = new Csr();
        csr.createCsr(Certificates.KeyType.RSA, 2048, "CN=my CSR with SAN", sanList);
        String csrPem = PemUtils.encodeObjectToPEM(csr.getCsr());
        logger.info("[generateCsrWithSAN] csr:\n" + csrPem);

        // Test some PemUtils tools
        assert PemUtils.convertPemToPKCS10CertificationRequest(csrPem) != null;
        assert PemUtils.encodeObjectToPEM(csr.getKeyPair().getPublic()).length()>0;

        Signer signerServer = new Signer();
        signerServer.setValidFrom(-1);
        signerServer.setValidTo(1);
        signerServer.addDomainName("other-name.example.com");
        signerServer.addIpAddress("127.0.0.1");
        signerServer.addIpAddress("::1");
        String serverCertificate = signerServer.signServer(
                PemUtils.encodeObjectToPEM(csr),
                TestLib.getCa().getCaPrivateKeyPEM(),
                TestLib.getCa().getCaCertificatePEM()
        );
        logger.info("[generateCsrWithSAN] serverCertificate:\n" + serverCertificate);
        X509Certificate serverX509 = PemUtils.getCertificateFromPem(serverCertificate);
        Objects.requireNonNull(
                Certificates.getSubjectAlternativeNames(serverX509)).forEach((v) ->
                logger.info("[generateCsrWithSAN] san: " + v)
        );

        assert PemUtils.encodeObjectToPEM((Certificate) serverX509).length()>0;

        Signer signerClient = new Signer();
        signerClient.setValidTo(1);
        signerClient.addRfc822Name("john.doe@example.com");
        signerClient.addUri("urn:uuid:" + UUID.randomUUID().toString());
        String clientCertificate = signerClient.signClient(
                PemUtils.encodeObjectToPEM(csr),
                TestLib.getCa().getCaPrivateKeyPEM(),
                TestLib.getCa().getCaCertificatePEM()
        );
        logger.info("[generateCsrWithSAN] clientCertificate:\n" + clientCertificate);
        X509Certificate clientX509 = PemUtils.getCertificateFromPem(clientCertificate);
        Objects.requireNonNull(
                Certificates.getSubjectAlternativeNames(clientX509)).forEach((v) ->
                logger.info("[generateCsrWithSAN] san: " + v)
        );
    }

    @Test
    public void testEC () throws Exception {
        KeyPair keyPair = KeyUtils.generateKeypairEC("ECDSA", "prime256v1");
        assert keyPair != null;

        Csr csr = new Csr();
        csr.createCsr(Certificates.KeyType.EC, "CN=ec test");
        PKCS10CertificationRequest pkcs10 = csr.getCsr();
        assert pkcs10 != null;
        logger.info("[testEC] pkcs10:\n" + PemUtils.encodeObjectToPEM(pkcs10));
    }
}
