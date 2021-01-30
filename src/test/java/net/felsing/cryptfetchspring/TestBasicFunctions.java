package net.felsing.cryptfetchspring;

import com.fasterxml.jackson.core.JsonProcessingException;
import net.felsing.cryptfetchspring.crypto.certs.*;
import net.felsing.cryptfetchspring.crypto.config.Configuration;
import net.felsing.cryptfetchspring.crypto.config.Constants;
import net.felsing.cryptfetchspring.crypto.util.JsonUtils;
import net.felsing.cryptfetchspring.crypto.util.PemUtils;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.security.KeyPair;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;


class TestBasicFunctions {
    private static final Logger logger = LoggerFactory.getLogger(TestBasicFunctions.class);

    private static TestLib testLib;
    private static Configuration config;


    @BeforeAll
    static void initTests() throws Exception {
        File filePkiPath = new File(TestLib.pkiPath);
        if (!filePkiPath.isDirectory()) {
            if (!filePkiPath.mkdir()) {
                throw new IOException(String.format("Cannot create dir %s", TestLib.pkiPath));
            }
        }
        testLib = TestLib.getInstance(TestLib.pkiPath);
        config = new Configuration();
    }

    /*
    @AfterAll
    static void cleanUp () throws IOException {
        File filePkiPath = new File(TestLib.pkiPath);
        if (!TestLib.deleteDirectory(filePkiPath)) {
            throw new IOException(String.format("Cannot delete dir %s", TestLib.pkiPath));
        }
    }
    */

    @Test
    void testServerConfig() {
        final ServerConfig localServerConfig = ServerConfig.getServerConfig();
        assertNotNull(localServerConfig);
    }

    @Test
    void encrypt() throws Exception {
        final HashMap<String, String> clientCert = testLib.genClientCertificate("client Cert for encryption");

        final String plainText = "Hello world! Umlaute: äöüÄÖÜß€";
        byte[] bPlainText = plainText.getBytes();

        final RSAPrivateKey privateKey = PemUtils.getPrivateKeyFromPem(clientCert.get("privateKey"));
        final X509Certificate certificate = PemUtils.getCertificateFromPem(clientCert.get("certificate"));
        final EncryptAndDecrypt encryptAndDecrypt = new EncryptAndDecrypt();

        final String encryptedText = encryptAndDecrypt.encryptPem(certificate, bPlainText);

        final byte[] bDecryptedText = encryptAndDecrypt.decrypt(privateKey, certificate, encryptedText);

        final String decryptedText = new String(bDecryptedText);

        if (logger.isInfoEnabled()) {
            logger.info("[encrypt] plainText: " + plainText);
            logger.info("[encrypt] decryptedText: " + decryptedText);
        }

        assertEquals(decryptedText, plainText);
    }

    @Test
    void cmsSign()
            throws Exception {
        final HashMap<String, String> clientCert = testLib.genClientCertificate("cert1");

        final String plainText = "Hello world! Umlaute: äöüÄÖÜß€";
        byte[] bPlainText = plainText.getBytes();

        final KeyPair keyPair = PemUtils.getKeyPair(clientCert.get("privateKey"), clientCert.get("certificate"));
        final X509Certificate cert = PemUtils.getCertificateFromPem(clientCert.get("certificate"));

        final CmsSign cmsSign = new CmsSign();
        final CMSSignedData signedText = cmsSign.signCmsEnveloped(keyPair, cert, bPlainText);
        assert PemUtils.encodeObjectToPEM(signedText).length() > 0;

        final CMSSignedData signedTextDetached = cmsSign.signCmsDetached(keyPair, cert, bPlainText);
        assert signedTextDetached != null;

        final CmsSign.Result result = cmsSign.verifyCmsSignature(signedText, TestLib.getCaCertificate());
        logger.info("[sign] isVerifyOk:  ".concat(Boolean.toString(result.isVerifyOk())));
        logger.info("[sign] signed Text: ".concat(new String(result.getContent())));
        final int[] count = new int[1];
        result.getCertificates().forEach((k) -> count[0] = count[0] + 1);

        assertEquals(1, count[0]);
        assertTrue(result.isVerifyOk());
    }


    @Test
    void generateCsrWithSAN() throws Exception {
        final List<GeneralName> sanList = new ArrayList<>();
        // this SAN will be thrown away by signer
        sanList.add(new GeneralName(GeneralName.dNSName, "name.example.com"));
        final Csr csr = new Csr();
        csr.createCsr(Constants.KeyType.RSA, 2048, "CN=my CSR with SAN", sanList);
        final String csrPem = PemUtils.encodeObjectToPEM(csr.getCsr());
        assertTrue(csrPem.length() > 0);

        // Test some PemUtils tools
        assertNotNull(PemUtils.convertPemToPKCS10CertificationRequest(csrPem));
        assertTrue(PemUtils.encodeObjectToPEM(csr.getKeyPair().getPublic()).length() > 0);

        final Signer signerServer = new Signer();
        signerServer.setValidFrom(-1);
        final int days = Integer.parseInt(config.getConfig().getProperty("certificate.days"));
        signerServer.setValidTo(days);
        signerServer.addDomainName("other-name.example.com");
        signerServer.addIpAddress("127.0.0.1");
        signerServer.addIpAddress("::1");
        String serverCertificate = signerServer.signServer(
                PemUtils.encodeObjectToPEM(csr.getCsr()),
                TestLib.getCa().getCaPrivateKeyPEM(),
                TestLib.getCa().getCaCertificatePEM()
        );
        assertTrue(serverCertificate.length() > 0);

        final X509Certificate serverX509 = PemUtils.getCertificateFromPem(serverCertificate);
        Objects.requireNonNull(
                Certificates.getSubjectAlternativeNames(serverX509)).forEach((v) -> assertTrue(v.length() > 0));

        assertTrue(PemUtils.encodeObjectToPEM((Certificate) serverX509).length() > 0);

        final Signer signerClient = new Signer();
        signerClient.setValidTo(days);
        signerClient.addRfc822Name("john.doe@example.com");
        signerClient.addUri("urn:uuid:" + UUID.randomUUID().toString());
        String clientCertificate = signerClient.signClient(
                PemUtils.encodeObjectToPEM(csr.getCsr()),
                TestLib.getCa().getCaPrivateKeyPEM(),
                TestLib.getCa().getCaCertificatePEM()
        );
        assertTrue(clientCertificate.length() > 0);

        final X509Certificate clientX509 = PemUtils.getCertificateFromPem(clientCertificate);
        Objects.requireNonNull(
                Certificates.getSubjectAlternativeNames(clientX509)).forEach((v) -> assertTrue(v.length() > 0));
    }

    @Test
    void testEC() throws Exception {
        final KeyPair keyPair = KeyUtils.generateKeypairEC("ECDSA", "prime256v1");
        assertNotNull(keyPair);

        final Csr csr = new Csr();
        csr.createCsr(Constants.KeyType.EC, "CN=ec test");
        PKCS10CertificationRequest pkcs10 = csr.getCsr();
        assertNotNull(pkcs10);

        final String pkcs10pem = PemUtils.encodeObjectToPEM(pkcs10);
        assertTrue(pkcs10pem.length() > 300);
        logger.info(pkcs10pem);
    }

    @Test
    void testDefaultConfig() throws JsonProcessingException {
        final Map<String, Object> configMap = ServerConfig.createDefaultConfig();
        final String configJson = JsonUtils.map2json(configMap);
        assertTrue(configJson.length() > 0);
    }

    private Certificates buildSelfSignedCertificate() {
        final Certificates certificates = new Certificates();
        certificates.setValidForDays(1);
        certificates.setOcspResponderUrl("http://localhost/ocsp");
        certificates.setCaIssuersUri("http://localhost/issuer");
        return certificates;
    }

    @Test
    void testSelfSignedCertificateEC() throws Exception {
        final Certificates certificates = buildSelfSignedCertificate();
        certificates.createSelfSignedCertificateEC("CN=My Selfsigned Cert EC", 256);
        final KeyPair keyPair = certificates.getKeyPair();
        final X509Certificate x509Certificate = certificates.getX509Certificate();
        assertNotNull(keyPair);
        assertNotNull(x509Certificate);
        logger.info("testSelfSignedCertificateEC:\n{}", PemUtils.encodeObjectToPEM(x509Certificate));
    }

    @Test
    void testSelfSignedCertificateRSA() throws Exception {
        final Certificates certificates = buildSelfSignedCertificate();
        certificates.createSelfSignedCertificateRSA("CN=My Selfsigned Cert RSA", 2048);
        final KeyPair keyPair = certificates.getKeyPair();
        final X509Certificate x509Certificate = certificates.getX509Certificate();
        assertNotNull(keyPair);
        assertNotNull(x509Certificate);
        logger.info("testSelfSignedCertificateRSA:\n{}", PemUtils.encodeObjectToPEM(x509Certificate));
    }

    @Test
    void testGenErrorString() {
        final String res = JsonUtils.genErrorString("test");
        assertNotNull(res);
    }

    @Test
    void testSerialize() throws Exception {
        final TestClass testClass = new TestClass();
        testClass.setS1("blah");
        testClass.setS2("fasel");
        final byte[] serialized = JsonUtils.serialize(testClass);
        final TestClass deserialize = JsonUtils.deserialize(serialized);

        assertNotNull(deserialize.getS1());
        assertNotNull(deserialize.getS2());
        logger.info(deserialize.getS1());
        logger.info(deserialize.getS2());
    }

}
