package net.felsing.cryptfetchspring;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import net.felsing.cryptfetchspring.crypto.certs.*;
import net.felsing.cryptfetchspring.crypto.util.PemUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.actuate.trace.http.HttpTrace;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.test.context.TestExecutionListeners;
import org.springframework.test.context.event.annotation.BeforeTestMethod;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.util.HashMap;
import java.util.Map;


@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, classes = CryptFetchSpringApplication.class)
class TestWebApplication {
    private static Logger logger = LogManager.getLogger(TestWebApplication.class);

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

            ObjectMapper mapper = new ObjectMapper();
            Map<String, Object> map = mapper.readValue(config, new TypeReference<>(){});
            Map<String,Object> configMap = (Map<String,Object>)map.get("config");
            Map<String,Object> remotekeystore = (Map<String,Object>)configMap.get("remotekeystore");
            ca = (String)remotekeystore.get("ca");
            String serverCertificatePem = (String)remotekeystore.get("server");
            serverCertificate = PemUtils.getCertificateFromPem(serverCertificatePem);
        }
    }


    @BeforeAll
    static void initTests () {
        try {
            testLib = TestLib.getInstance();
            CryptFetchSpringApplication.addInitHooks();
        } catch (Exception e) {
            logger.error("BeforeAll failed");
            logger.error(e);
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
        ObjectMapper reqMapper = new ObjectMapper();
        String jsonResult = reqMapper.writerWithDefaultPrettyPrinter().writeValueAsString(map);
        String encrypted = encryptAndDecrypt.encryptPem(null, null, serverCertificate, jsonResult.getBytes());

        String response = this.restTemplate.postForObject(url, encrypted, String.class);

        ObjectMapper respMapper = new ObjectMapper();
        return respMapper.readValue(response, new TypeReference<>(){});
    }


    @Test
    public void testLogin () throws Exception {
        loadConfig();

        String username = "myUserName";
        String password = "myPassword";
        Csr csr = testLib.genCsr("CN=cert1");
        String pemCsr = PemUtils.encodeObjectToPEM(csr);

        Map<String, String> respMap = login(username, password, pemCsr);

        boolean authenticated = Boolean.parseBoolean(respMap.get("authenticated"));
        String certificate = respMap.get("certificate");
        logger.info("authenticated: " + authenticated);
        logger.info("certificate:\n" + certificate);

        assert authenticated;
        assert certificate != null;
    }


    private String doMessage (KeyPair senderKeyPair, X509Certificate senderCert, byte[] message)
            throws Exception {
        String url = "http://localhost:" + port + "/message";

        EncryptAndDecrypt encryptAndDecrypt = new EncryptAndDecrypt();
        Cms cms = new Cms();

        CMSSignedData cmsSignedData = cms.signCmsEnveloped(senderKeyPair, senderCert, message);

        String encrypted = encryptAndDecrypt.encryptPem(senderKeyPair.getPrivate(),
                senderCert, serverCertificate, cmsSignedData.getEncoded());

        return this.restTemplate.postForObject(url, encrypted, String.class);
    }

    @Test
    public void testMessage () throws Exception {
        String username = "myUsername2";
        String password = "myPassword2";
        Csr csr = testLib.genCsr("CN=cert2");
        String pemCsr = PemUtils.encodeObjectToPEM(csr);

        String plainTextSend = "Hello world! Umlaute: äöüÄÖÜß€";

        Map<String,String> loginResp = login(username, password, pemCsr);

        String clientCertPem = loginResp.get("certificate");
        X509Certificate clientCert = PemUtils.getCertificateFromPem(clientCertPem);

        String response = doMessage(csr.getKeyPair(), clientCert, plainTextSend.getBytes());
        EncryptAndDecrypt encryptAndDecrypt = new EncryptAndDecrypt();
        byte[] decryptedResponse = encryptAndDecrypt.decrypt(
                csr.getKeyPair().getPrivate(),
                clientCert,
                response
        );
        Cms cms = new Cms();
        Cms.Result result = cms.verifyCmsSignature(
                new CMSSignedData(decryptedResponse),
                PemUtils.getCertificateFromPem(ca)
        );

        String content = new String(result.getContent());
        logger.info("[testMessage] response content: " + content);
        logger.info("[testMessage] response validated: " + result.isVerifyOk());

        //assert content.matches(".*foo.*");
        assert result.isVerifyOk();
    }
}
