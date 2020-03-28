package net.felsing.cryptfetchspring;

import net.felsing.cryptfetchspring.crypto.certs.*;
import net.felsing.cryptfetchspring.crypto.util.PemUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
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
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.util.HashMap;


@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class TestWebApplication {
    private static Logger logger = LogManager.getLogger(TestWebApplication.class);

    private static TestLib testLib;
    private static String config=null;

    @LocalServerPort
    private int port;
    @Autowired
    private TestRestTemplate restTemplate;
    @Autowired
    private CryptFetchSpringApplication controller;

    private void loadConfig () {
        if (config==null) {
            String url = "http://localhost:" + port + "/config";
            config = restTemplate.getForObject(url, String.class);
            logger.info(config);
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
        Csr csr = testLib.genCsr("CN=cert1");
        KeyPair keyPair = csr.getKeyPair();
        String pemCsr = PemUtils.encodeObjectToPEM(csr);

        String request = "";
        //String response = this.restTemplate.postForObject(url, request, String.class);
    }

}
