package net.felsing.cryptfetchspring;

import com.fasterxml.jackson.core.JsonProcessingException;
import net.felsing.cryptfetchspring.crypto.certs.CmsSign;
import net.felsing.cryptfetchspring.crypto.certs.Csr;
import net.felsing.cryptfetchspring.crypto.certs.EncryptAndDecrypt;
import net.felsing.cryptfetchspring.crypto.util.CheckedCast;
import net.felsing.cryptfetchspring.crypto.util.JsonUtils;
import net.felsing.cryptfetchspring.crypto.util.PemUtils;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.web.server.LocalServerPort;

import java.io.File;
import java.io.IOException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;


@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, classes = CryptFetchSpringApplication.class)
class TestWebApplication {
    private static final Logger logger = LoggerFactory.getLogger(TestWebApplication.class);

    private static TestLib testLib;
    private static String config=null;
    private static String ca=null;
    private static X509Certificate serverCertificate=null;

    @LocalServerPort
    private int port;

    @Autowired
    private TestRestTemplate restTemplate;
    @Autowired
    private CryptFetchSpringApplication controller;


    private void loadConfig () throws JsonProcessingException, CertificateException {
        if (config==null) {
            final String url = String.format("http://localhost:%d/config", port);
            config = restTemplate.getForObject(url, String.class);
            final Map<String,Object> map = JsonUtils.json2map(config);

            @SuppressWarnings("rawtypes")
            final Map<String,Object> configMap = CheckedCast.castToMapOf(
                    String.class,
                    Object.class,
                    (Map)map.get("config")
            );
            @SuppressWarnings("rawtypes")
            final Map<String,Object> remotekeystore = CheckedCast.castToMapOf(
                    String.class,
                    Object.class,
                    (Map)configMap.get("remotekeystore")
            );

            ca = (String)remotekeystore.get("ca");
            final String serverCertificatePem = (String)remotekeystore.get("server");
            serverCertificate = PemUtils.getCertificateFromPem(serverCertificatePem);
        }
    }


    @BeforeAll
    static void initTests () throws Exception {
        File filePkiPath = new File(TestLib.pkiPath);
        if (!filePkiPath.isDirectory()) {
            if (!filePkiPath.mkdir()) {
                throw new IOException(String.format("Cannot create dir %s", TestLib.pkiPath));
            }
        }
        testLib = TestLib.getInstance(TestLib.pkiPath);
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
    void contextLoads() {

        assertNotNull (controller);
    }


    @Test
    void testGetRoot() {
        final String url = "http://localhost:" + port + "/";
        final String expectedResult = "getRoot";
        assertTrue(this.restTemplate.getForObject(url, String.class).contains(expectedResult));
    }


    private Map<String, String> login (String username, String password, String pemCsr)
        throws Exception {
        final String url = String.format("http://localhost:%d/login", port);

        final EncryptAndDecrypt encryptAndDecrypt = new EncryptAndDecrypt();

        final HashMap<String,String> map = new HashMap<>();
        map.put("username", username);
        map.put("password", password);
        map.put("csr", pemCsr);
        final String jsonResult = JsonUtils.map2json(map);
        final String encrypted = encryptAndDecrypt.encryptPem(null, null, serverCertificate, jsonResult.getBytes());

        final String response = this.restTemplate.postForObject(url, encrypted, String.class);

        return CheckedCast.castToMapOf(String.class, String.class, JsonUtils.json2map(response));
    }


    @Test
    void testLogin () throws Exception {
        loadConfig();

        final String username = "myUserName";
        final String password = "myPassword";
        final Csr csr = testLib.genCsr("CN=cert1");
        final String pemCsr = PemUtils.encodeObjectToPEM(csr.getCsr());

        final Map<String, String> respMap = login(username, password, pemCsr);

        final boolean authenticated = Boolean.parseBoolean(respMap.get("authenticated"));
        final String certificate = respMap.get("certificate");

        assertTrue(authenticated);
        assertNotNull(certificate);
    }


    private String doMessage (String path, KeyPair senderKeyPair, X509Certificate senderCert, byte[] message)
            throws Exception {
        final String url = String.format("http://localhost:%d%s", port, path);
        final EncryptAndDecrypt encryptAndDecrypt = new EncryptAndDecrypt();
        final CmsSign cmsSign = new CmsSign();

        final CMSSignedData cmsSignedData = cmsSign.signCmsEnveloped(senderKeyPair, senderCert, message);

        final String encrypted = encryptAndDecrypt.encryptPem(senderKeyPair.getPrivate(),
                senderCert, serverCertificate, cmsSignedData.getEncoded());

        return this.restTemplate.postForObject(url, encrypted, String.class);
    }

    @Test
    void testMessage () throws Exception {
        final String username = "myUsername2";
        final String password = "myPassword2";
        final Csr csr = testLib.genCsr("CN=cert2");
        final String pemCsr = PemUtils.encodeObjectToPEM(csr.getCsr());

        final String plainTextSend = "Hello world! Umlaute: äöüÄÖÜß€";

        final Map<String,String> loginResp = login(username, password, pemCsr);

        final String clientCertPem = loginResp.get("certificate");
        final X509Certificate clientCert = PemUtils.getCertificateFromPem(clientCertPem);

        final String response = doMessage("/message", csr.getKeyPair(), clientCert, plainTextSend.getBytes());

        final byte[] decryptedResponse = decrypt(csr.getKeyPair().getPrivate(), clientCert, response);
        final CmsSign.Result result = validate(decryptedResponse);

        final String content = new String(result.getContent());
        if (logger.isInfoEnabled()) {
            logger.info(String.format("[testMessage] response content: %s", content));
            logger.info(String.format("[testMessage] response validated: %b", result.isVerifyOk()));
        }

        final Map<String, String> contentHashMap = CheckedCast.castToMapOf(String.class, String.class, JsonUtils.json2map(content));

        assertTrue(contentHashMap.containsKey("foo"));
        assertTrue(contentHashMap.containsValue("bar äöüÄÖÜß€"));
        assertTrue(result.isVerifyOk());
    }


    @Test
    void testRenew () throws Exception {
        final String username = "myUsername3";
        final String password = "myPassword3";

        // Build a valid certificate
        final Csr csr = testLib.genCsr("CN=cert3");
        final String pemCsr = PemUtils.encodeObjectToPEM(csr.getCsr());
        final Map<String,String> loginResp = login(username, password, pemCsr);

        final String clientCertPem = loginResp.get("certificate");
        final X509Certificate clientCert = PemUtils.getCertificateFromPem(clientCertPem);

        final String response = doMessage("/renew", csr.getKeyPair(), clientCert, pemCsr.getBytes());

        final byte[] decryptedText = decrypt(csr.getKeyPair().getPrivate(), clientCert, response);
        final CmsSign.Result result = validate(decryptedText);

        final Map<String,String> resultMap = CheckedCast.castToMapOf(String.class,String.class,
                JsonUtils.json2map(new String(result.getContent())));

        final String newCertPEM = resultMap.get("certificate");
        final X509Certificate newCert = PemUtils.getCertificateFromPem(newCertPEM);

        assertNotNull(newCert);
    }


    private byte[] decrypt (PrivateKey privateKey, X509Certificate x509Certificate, String encryptedText)
            throws IOException, CMSException {
        final EncryptAndDecrypt encryptAndDecrypt = new EncryptAndDecrypt();
        return encryptAndDecrypt.decrypt(
                privateKey,
                x509Certificate,
                encryptedText
        );
    }


    private CmsSign.Result validate (byte[] cmsSignedData)
            throws CertificateException, CMSException {
        final CmsSign cmsSign = new CmsSign();
        return cmsSign.verifyCmsSignature(
                new CMSSignedData(cmsSignedData),
                PemUtils.getCertificateFromPem(ca)
        );
    }

}
