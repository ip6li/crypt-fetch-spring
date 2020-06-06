package net.felsing.cryptfetchspring;

import com.fasterxml.jackson.core.JsonProcessingException;
import net.felsing.cryptfetchspring.crypto.certs.*;
import net.felsing.cryptfetchspring.crypto.util.CheckedCast;
import net.felsing.cryptfetchspring.crypto.util.JsonUtils;
import net.felsing.cryptfetchspring.crypto.util.PemUtils;
import org.slf4j.LoggerFactory;
import org.slf4j.Logger;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.web.server.LocalServerPort;
import java.io.IOException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;


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
            String url = "http://localhost:" + port + "/config";
            config = restTemplate.getForObject(url, String.class);
            Map<?,?> map = JsonUtils.json2map(config);

            @SuppressWarnings("rawtypes")
            Map<String,Object> configMap = CheckedCast.castToMapOf(
                    String.class,
                    Object.class,
                    (Map)map.get("config")
            );
            @SuppressWarnings("rawtypes")
            Map<String,Object> remotekeystore = CheckedCast.castToMapOf(
                    String.class,
                    Object.class,
                    (Map)configMap.get("remotekeystore")
            );

            ca = (String)remotekeystore.get("ca");
            String serverCertificatePem = (String)remotekeystore.get("server");
            serverCertificate = PemUtils.getCertificateFromPem(serverCertificatePem);
        }
    }


    @BeforeAll
    static void initTests () {
        try {
            testLib = TestLib.getInstance();
        } catch (Exception e) {
            logger.error("BeforeAll failed");
            logger.error(e.getMessage());
        }
    }


    @Test
    void contextLoads() {

        assert controller != null;
    }


    @Test
    public void testGetRoot() {
        String url = "http://localhost:" + port + "/";
        String expectedResult = "getRoot";
        assert this.restTemplate.getForObject(url, String.class).contains(expectedResult);
    }


    private Map<String, String> login (String username, String password, String pemCsr)
        throws Exception {
        String url = "http://localhost:" + port + "/login";

        EncryptAndDecrypt encryptAndDecrypt = new EncryptAndDecrypt();

        HashMap<String,String> map = new HashMap<>();
        map.put("username", username);
        map.put("password", password);
        map.put("csr", pemCsr);
        String jsonResult = JsonUtils.map2json(map);
        String encrypted = encryptAndDecrypt.encryptPem(null, null, serverCertificate, jsonResult.getBytes());

        String response = this.restTemplate.postForObject(url, encrypted, String.class);

        return CheckedCast.castToMapOf(String.class, String.class, JsonUtils.json2map(response));
    }


    @Test
    public void testLogin () throws Exception {
        loadConfig();

        String username = "myUserName";
        String password = "myPassword";
        Csr csr = testLib.genCsr("CN=cert1");
        String pemCsr = PemUtils.encodeObjectToPEM(csr.getCsr());

        Map<String, String> respMap = login(username, password, pemCsr);

        boolean authenticated = Boolean.parseBoolean(respMap.get("authenticated"));
        String certificate = respMap.get("certificate");

        assert authenticated;
        assert certificate != null;
    }


    private String doMessage (String path, KeyPair senderKeyPair, X509Certificate senderCert, byte[] message)
            throws Exception {
        String url = "http://localhost:" + port + path;

        EncryptAndDecrypt encryptAndDecrypt = new EncryptAndDecrypt();
        CmsSign cmsSign = new CmsSign();

        CMSSignedData cmsSignedData = cmsSign.signCmsEnveloped(senderKeyPair, senderCert, message);

        String encrypted = encryptAndDecrypt.encryptPem(senderKeyPair.getPrivate(),
                senderCert, serverCertificate, cmsSignedData.getEncoded());

        return this.restTemplate.postForObject(url, encrypted, String.class);
    }

    @Test
    public void testMessage () throws Exception {
        String username = "myUsername2";
        String password = "myPassword2";
        Csr csr = testLib.genCsr("CN=cert2");
        String pemCsr = PemUtils.encodeObjectToPEM(csr.getCsr());

        String plainTextSend = "Hello world! Umlaute: äöüÄÖÜß€";

        Map<String,String> loginResp = login(username, password, pemCsr);

        String clientCertPem = loginResp.get("certificate");
        X509Certificate clientCert = PemUtils.getCertificateFromPem(clientCertPem);

        String response = doMessage("/message", csr.getKeyPair(), clientCert, plainTextSend.getBytes());

        byte[] decryptedResponse = decrypt(csr.getKeyPair().getPrivate(), clientCert, response);
        CmsSign.Result result = validate(decryptedResponse);

        String content = new String(result.getContent());
        logger.info("[testMessage] response content: " + content);
        logger.info("[testMessage] response validated: " + result.isVerifyOk());

        //assert content.matches(".*foo.*");
        assert result.isVerifyOk();
    }


    @Test
    public void testRenew () throws Exception {
        String username = "myUsername3";
        String password = "myPassword3";

        // Build a valid certificate
        Csr csr = testLib.genCsr("CN=cert3");
        String pemCsr = PemUtils.encodeObjectToPEM(csr.getCsr());
        Map<String,String> loginResp = login(username, password, pemCsr);

        String clientCertPem = loginResp.get("certificate");
        X509Certificate clientCert = PemUtils.getCertificateFromPem(clientCertPem);

        String response = doMessage("/renew", csr.getKeyPair(), clientCert, pemCsr.getBytes());

        byte[] decryptedText = decrypt(csr.getKeyPair().getPrivate(), clientCert, response);
        CmsSign.Result result = validate(decryptedText);
        Map<String,String> resultMap = CheckedCast.castToMapOf(String.class,String.class,
                JsonUtils.json2map(new String(result.getContent())));

        String newCertPEM = resultMap.get("certificate");
        X509Certificate newCert = PemUtils.getCertificateFromPem(newCertPEM);
        assert newCert != null;
    }


    private byte[] decrypt (PrivateKey privateKey, X509Certificate x509Certificate, String encryptedText)
            throws IOException, CMSException {
        EncryptAndDecrypt encryptAndDecrypt = new EncryptAndDecrypt();
        return encryptAndDecrypt.decrypt(
                privateKey,
                x509Certificate,
                encryptedText
        );
    }


    private CmsSign.Result validate (byte[] cmsSignedData)
            throws CertificateException, CMSException {
        CmsSign cmsSign = new CmsSign();
        return cmsSign.verifyCmsSignature(
                new CMSSignedData(cmsSignedData),
                PemUtils.getCertificateFromPem(ca)
        );
    }

}
