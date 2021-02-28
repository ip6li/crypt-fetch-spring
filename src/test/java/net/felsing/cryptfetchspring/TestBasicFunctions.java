package net.felsing.cryptfetchspring;

import com.fasterxml.jackson.core.JsonProcessingException;
import net.felsing.cryptfetchspring.crypto.certs.*;
import net.felsing.cryptfetchspring.crypto.config.ConfigModel;
import net.felsing.cryptfetchspring.crypto.config.Configuration;
import net.felsing.cryptfetchspring.crypto.config.Constants;
import net.felsing.cryptfetchspring.crypto.util.LogEngine;
import net.felsing.cryptfetchspring.crypto.util.PemUtils;
import net.felsing.cryptfetchspring.models.ErrorModel;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.operator.OperatorCreationException;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.util.*;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.*;


class TestBasicFunctions {
    private static final LogEngine logger = LogEngine.getLogger(TestBasicFunctions.class);

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

    @AfterAll
    static void cleanUp () throws IOException {
        File filePkiPath = new File(TestLib.pkiPath);
        if (!TestLib.deleteDirectory(filePkiPath)) {
            throw new IOException(String.format("Cannot delete dir %s", TestLib.pkiPath));
        }
    }

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

            logger.info("[encrypt] plainText: " + plainText);
            logger.info("[encrypt] decryptedText: " + decryptedText);


        assertEquals(decryptedText, plainText);
    }

    @Test
    void cmsSign()
            throws CertificateException, InvalidKeySpecException, NoSuchAlgorithmException,
            OperatorCreationException, NoSuchProviderException, InvalidAlgorithmParameterException,
            IOException, CMSException {
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


    private void generateCsrWithSAN(Constants.KeyType mode, int size) throws Exception {

        final List<GeneralName> sanList = new ArrayList<>();
        // this SAN will be thrown away by signer
        sanList.add(new GeneralName(GeneralName.dNSName, "name.example.com"));
        final Csr csr = new Csr();
        csr.createCsr(mode, size, String.format("CN=my CSR with SAN (%s)", mode), sanList);
        final String csrPem = PemUtils.encodeObjectToPEM(csr.getCsr());
        logger.info(String.format("generateCsrWithSAN (CSR): %s\n%s", mode, csrPem));
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
        logger.info(String.format("generateCsrWithSAN (Cert): %s\n%s", mode, clientCertificate));
        Objects.requireNonNull(
                Certificates.getSubjectAlternativeNames(clientX509)).forEach((v) -> assertTrue(v.length() > 0));
    }

    @Test
    void generateCsrWithSAN() throws Exception {
        for (Constants.KeyType i: Constants.KeyType.values()) {
            generateCsrWithSAN(i, 2048);
        }
    }

    @Test
    void testDefaultConfig() throws IOException {
        final ConfigModel configMap = ServerConfig.createDefaultConfig();
        assertTrue(configMap.getAuthURL().length() > 0);
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
        logger.info(String.format("testSelfSignedCertificateEC:\n%s", PemUtils.encodeObjectToPEM(x509Certificate)));
    }

    @Test
    void testSelfSignedCertificateRSA() throws Exception {
        for (int i=0; i<2; i++) {
            boolean pss = i==1;
            final Certificates certificates = buildSelfSignedCertificate();
            certificates.createSelfSignedCertificateRSA(
                    String.format("CN=My Selfsigned Cert RSA (PSS: %b)", pss),
                    2048,
                    pss
            );
            final KeyPair keyPair = certificates.getKeyPair();
            final X509Certificate x509Certificate = certificates.getX509Certificate();
            assertNotNull(keyPair);
            assertNotNull(x509Certificate);
            logger.info(String.format(
                    "testSelfSignedCertificateRSA (PSS: %b):\n%s",
                    pss,
                    PemUtils.encodeObjectToPEM(x509Certificate))
            );
        }
    }

    @Test
    void testGenErrorString() throws JsonProcessingException {
        final String msg = "foo";
        final ErrorModel res = new ErrorModel(msg);
        assertThat(res.get(), containsString(msg));
        logger.info(String.format("testGenErrorString: %s", new String(res.serialize())));
        assertThat(new String(res.serialize()), containsString(msg));
    }

    @Test
    void testSerialize() throws Exception {
        final TestClass testClass = new TestClass();

        testClass.setS1("blah");
        testClass.setS2("fasel");
        final byte[] serialized = testClass.serializes();

        final TestClass deserialize = TestClass.deserialize(serialized);

        assertNotNull(deserialize.getS1());
        assertNotNull(deserialize.getS2());
        logger.info(deserialize.getS1());
        logger.info(deserialize.getS2());
    }

}
