package net.felsing.cryptfetchspring;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import net.felsing.cryptfetchspring.crypto.certs.*;
import net.felsing.cryptfetchspring.crypto.util.PemUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.actuate.trace.http.HttpTrace;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.test.context.event.annotation.BeforeTestMethod;

import java.security.KeyPair;
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
    private static Csr csr=null;


    @LocalServerPort
    private int port;
    @Autowired
    private TestRestTemplate restTemplate;
    @Autowired
    private CryptFetchSpringApplication controller;

    private void loadConfig () throws JsonProcessingException, CertificateException {
        if (config==null) {
            port = 8080;
            String url = "http://localhost:" + port + "/config";
            config = restTemplate.getForObject(url, String.class);

            ObjectMapper mapper = new ObjectMapper();
            Map<String, Object> map = mapper.readValue(config, new TypeReference<>(){});
            Map<String,Object> configMap = (Map<String,Object>)map.get("config");
            Map<String,Object> remotekeystore = (Map<String,Object>)configMap.get("remotekeystore");
            ca = (String)remotekeystore.get("ca");
            String serverCertificatePem = (String)remotekeystore.get("ca");
            serverCertificate = PemUtils.getCertificateFromPem(serverCertificatePem);
        }
    }


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
    void contextLoads() {

        assert controller != null;
    }


    @Test
    public void testGetRoot() {
        String url = "http://localhost:" + port + "/";
        String expectedResult = "getRoot";
        assert this.restTemplate.getForObject(url, String.class).contains(expectedResult);
    }


    @Test
    public void testLogin () throws Exception {
        loadConfig();

        String url = "http://localhost:" + port + "/login";
        String username = "myUserName";
        String password = "myPassword";
        csr = testLib.genCsr("CN=cert1");
        String pemCsr = PemUtils.encodeObjectToPEM(csr);
        EncryptAndDecrypt encryptAndDecrypt = new EncryptAndDecrypt();

        HashMap<String,String> map = new HashMap<>();
        map.put("username", username);
        map.put("password", password);
        map.put("csr", pemCsr);
        ObjectMapper mapper = new ObjectMapper();
        String jsonResult = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(map);
        byte[] encrypted = encryptAndDecrypt.encrypt(null, null, serverCertificate, jsonResult.getBytes());
        String request = PemUtils.encodeObjectToPEM(new CMSEnvelopedData(encrypted));
        logger.info("[testLogin] request: " + request);
        String response = this.restTemplate.postForObject(url, request, String.class);
        logger.info("[testLogin] response: " + response);
    }

}
