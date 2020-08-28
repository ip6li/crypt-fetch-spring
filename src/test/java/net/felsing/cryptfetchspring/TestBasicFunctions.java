package net.felsing.cryptfetchspring;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.TSFBuilder;
import net.felsing.cryptfetchspring.crypto.certs.*;
import net.felsing.cryptfetchspring.crypto.config.Configuration;
import net.felsing.cryptfetchspring.crypto.config.Constants;
import net.felsing.cryptfetchspring.crypto.util.JsonUtils;
import net.felsing.cryptfetchspring.crypto.util.PemUtils;
import org.json.JSONException;
import org.json.JSONObject;
import org.slf4j.LoggerFactory;
import org.slf4j.Logger;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import java.io.Serializable;
import java.security.KeyPair;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.util.*;


@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class TestBasicFunctions {
    private static final Logger logger = LoggerFactory.getLogger(TestBasicFunctions.class);

    private static TestLib testLib;
    private static Configuration config;

    @BeforeAll
    static void initTests() {
        try {
            testLib = TestLib.getInstance();
            config = new Configuration();
        } catch (Exception e) {
            logger.error("BeforeAll failed");
            logger.error(e.getMessage());
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

        if (logger.isInfoEnabled()) {
            logger.info("[encrypt] plainText: " + plainText);
            logger.info("[encrypt] decryptedText: " + decryptedText);
        }

        assert plainText.equals(decryptedText);
    }

    @Test
    void cmsSign()
            throws Exception {
        HashMap<String, String> clientCert = testLib.genClientCertificate("cert1");

        String plainText = "Hello world! Umlaute: äöüÄÖÜß€";
        byte[] bPlainText = plainText.getBytes();

        KeyPair keyPair = PemUtils.getKeyPair(clientCert.get("privateKey"), clientCert.get("certificate"));
        X509Certificate cert = PemUtils.getCertificateFromPem(clientCert.get("certificate"));

        CmsSign cmsSign = new CmsSign();
        CMSSignedData signedText = cmsSign.signCmsEnveloped(keyPair, cert, bPlainText);
        assert PemUtils.encodeObjectToPEM(signedText).length() > 0;

        CMSSignedData signedTextDetached = cmsSign.signCmsDetached(keyPair, cert, bPlainText);
        assert signedTextDetached != null;

        CmsSign.Result result = cmsSign.verifyCmsSignature(signedText, TestLib.getCaCertificate());
        logger.info("[sign] isVerifyOk:  ".concat(Boolean.toString(result.isVerifyOk())));
        logger.info("[sign] signed Text: ".concat(new String(result.getContent())));
        int[] count = new int[1];
        result.getCertificates().forEach((k) -> count[0] = count[0] + 1);
        assert count[0] == 1;
        assert result.isVerifyOk();
    }


    @Test
    void generateCsrWithSAN() throws Exception {
        List<GeneralName> sanList = new ArrayList<>();
        // this SAN will be thrown away by signer
        sanList.add(new GeneralName(GeneralName.dNSName, "name.example.com"));
        Csr csr = new Csr();
        csr.createCsr(Constants.KeyType.RSA, 2048, "CN=my CSR with SAN", sanList);
        String csrPem = PemUtils.encodeObjectToPEM(csr.getCsr());
        assert csrPem.length()>0;

        // Test some PemUtils tools
        assert PemUtils.convertPemToPKCS10CertificationRequest(csrPem) != null;
        assert PemUtils.encodeObjectToPEM(csr.getKeyPair().getPublic()).length() > 0;

        Signer signerServer = new Signer();
        signerServer.setValidFrom(-1);
        int days = Integer.parseInt(config.getConfig().getProperty("certificate.days"));
        signerServer.setValidTo(days);
        signerServer.addDomainName("other-name.example.com");
        signerServer.addIpAddress("127.0.0.1");
        signerServer.addIpAddress("::1");
        String serverCertificate = signerServer.signServer(
                PemUtils.encodeObjectToPEM(csr.getCsr()),
                TestLib.getCa().getCaPrivateKeyPEM(),
                TestLib.getCa().getCaCertificatePEM()
        );
        assert serverCertificate.length()>0;
        X509Certificate serverX509 = PemUtils.getCertificateFromPem(serverCertificate);
        Objects.requireNonNull(
                Certificates.getSubjectAlternativeNames(serverX509)).forEach((v) -> {
            assert v.length()>0;
        });

        assert PemUtils.encodeObjectToPEM((Certificate) serverX509).length() > 0;

        Signer signerClient = new Signer();
        signerClient.setValidTo(days);
        signerClient.addRfc822Name("john.doe@example.com");
        signerClient.addUri("urn:uuid:" + UUID.randomUUID().toString());
        String clientCertificate = signerClient.signClient(
                PemUtils.encodeObjectToPEM(csr.getCsr()),
                TestLib.getCa().getCaPrivateKeyPEM(),
                TestLib.getCa().getCaCertificatePEM()
        );
        assert clientCertificate.length()>0;
        X509Certificate clientX509 = PemUtils.getCertificateFromPem(clientCertificate);
        Objects.requireNonNull(
                Certificates.getSubjectAlternativeNames(clientX509)).forEach((v) -> {
            assert v.length() > 0;
        });
    }

    @Test
    public void testEC() throws Exception {
        KeyPair keyPair = KeyUtils.generateKeypairEC("ECDSA", "prime256v1");
        assert keyPair != null;

        Csr csr = new Csr();
        csr.createCsr(Constants.KeyType.EC, "CN=ec test");
        PKCS10CertificationRequest pkcs10 = csr.getCsr();
        assert pkcs10 != null;
        String pkcs10pem = PemUtils.encodeObjectToPEM(pkcs10);
        assert pkcs10pem.length() > 300;
        logger.info(pkcs10pem);
    }

    @Test
    public void testDefaultConfig() throws JsonProcessingException {
        Map<String, Object> configMap = ServerConfig.createDefaultConfig();
        String configJson = JsonUtils.map2json(configMap);
        assert configJson.length() > 0;
    }

    private Certificates buildSelfSignedCertificate () {
        Certificates certificates = new Certificates();
        certificates.setValidForDays(1);
        certificates.setOcspResponderUrl("http://localhost/ocsp");
        certificates.setCaIssuersUri("http://localhost/issuer");
        return certificates;
    }

    @Test
    public void testSelfSignedCertificateEC() throws Exception {
        Certificates certificates = buildSelfSignedCertificate();
        certificates.createSelfSignedCertificateEC("CN=My Selfsigned Cert EC", 256);
        KeyPair keyPair = certificates.getKeyPair();
        X509Certificate x509Certificate = certificates.getX509Certificate();
        assert keyPair != null;
        assert x509Certificate != null;
        logger.info("testSelfSignedCertificateEC:\n{}", PemUtils.encodeObjectToPEM(x509Certificate));
    }

    @Test
    public void testSelfSignedCertificateRSA() throws Exception {
        Certificates certificates = buildSelfSignedCertificate();
        certificates.createSelfSignedCertificateRSA("CN=My Selfsigned Cert RSA", 2048);
        KeyPair keyPair = certificates.getKeyPair();
        X509Certificate x509Certificate = certificates.getX509Certificate();
        assert keyPair != null;
        assert x509Certificate != null;
        logger.info("testSelfSignedCertificateRSA:\n{}", PemUtils.encodeObjectToPEM(x509Certificate));
    }

    @Test
    public void testGenErrorString () {
        String res = JsonUtils.genErrorString("test");
        assert res!=null;
    }

    @Test
    public void testSerialize () throws Exception {
        TestClass testClass = new TestClass();
        testClass.setS1("blah");
        testClass.setS2("fasel");
        byte[] serialized = JsonUtils.serialize(testClass);
        TestClass deserialize = JsonUtils.deserialize(serialized);
        System.out.println(deserialize.getS1());
        System.out.println(deserialize.getS2());
    }
}
