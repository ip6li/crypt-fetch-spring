package net.felsing.cryptfetchspring;

import com.fasterxml.jackson.annotation.JsonGetter;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonRootName;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import net.felsing.cryptfetchspring.crypto.certs.CmsSign;
import net.felsing.cryptfetchspring.crypto.certs.Csr;
import net.felsing.cryptfetchspring.crypto.certs.EncryptAndDecrypt;
import net.felsing.cryptfetchspring.crypto.config.ConfigModel;
import net.felsing.cryptfetchspring.crypto.util.PemUtils;
import net.felsing.cryptfetchspring.login.LoginModel;
import net.felsing.cryptfetchspring.models.PayloadDemoModel;
import net.felsing.cryptfetchspring.models.RenewModel;
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

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashMap;

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

    @JsonRootName(value = "loginresponse")
    private static class LoginResponse {
        private final HashMap<String, String> resp = new HashMap<>();

        public LoginResponse (
                @JsonProperty("authenticated") boolean authenticated,
                @JsonProperty("certificate") String certificate
        ) {
            resp.put("authenticated", Boolean.toString(authenticated));
            resp.put("certificate", certificate);
        }

        @JsonGetter
        public HashMap<String, String> getResp() { return resp; }

        public static LoginResponse deserialize(String json) throws JsonProcessingException {
            ObjectMapper om = new ObjectMapper();
            return om.readerFor(LoginResponse.class).readValue(json);
        }
    }


    private void loadConfig2 ()
            throws IOException, CertificateException {
        final String url = String.format("http://localhost:%d/config", port);
        config = restTemplate.getForObject(url, String.class);
        InputStream targetStream = new ByteArrayInputStream(config.getBytes());
        ConfigModel configModel = ConfigModel.deserialize(targetStream);
        HashMap<String, String> remotekeystore = configModel.getRemotekeystore();
        ca = remotekeystore.get("ca");
        final String serverCertificatePem = remotekeystore.get("server");
        serverCertificate = PemUtils.getCertificateFromPem(serverCertificatePem);
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


    @AfterAll
    static void cleanUp () throws IOException {
        File filePkiPath = new File(TestLib.pkiPath);
        if (!TestLib.deleteDirectory(filePkiPath)) {
            throw new IOException(String.format("Cannot delete dir %s", TestLib.pkiPath));
        }
    }


    @Test
    void testGetRoot() {
        final String url = "http://localhost:" + port + "/";
        final String expectedResult = "getRoot";
        assertTrue(this.restTemplate.getForObject(url, String.class).contains(expectedResult));
    }


    private LoginResponse login (String username, String password, String pemCsr)
        throws Exception {
        final String url = String.format("http://localhost:%d/login", port);

        final LoginModel loginModel = new LoginModel(username, password, pemCsr);
        final EncryptAndDecrypt encryptAndDecrypt = new EncryptAndDecrypt();

        final byte[] jsonResult = loginModel.serialize();
        final String encrypted = encryptAndDecrypt.encryptPem(null, null, serverCertificate, jsonResult);

        final String response = this.restTemplate.postForObject(url, encrypted, String.class);
        return LoginResponse.deserialize(response);
    }


    @Test
    void testLogin () throws Exception {
        loadConfig2();

        final String username = "myUserName";
        final String password = "myPassword";
        final Csr csr = testLib.genCsr("CN=cert1");
        final String pemCsr = PemUtils.encodeObjectToPEM(csr.getCsr());

        final LoginResponse respMap = login(username, password, pemCsr);

        final boolean authenticated = Boolean.parseBoolean(respMap.getResp().get("authenticated"));
        final String certificate = respMap.getResp().get("certificate");

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

        final LoginResponse loginResp = login(username, password, pemCsr);

        final String clientCertPem = loginResp.getResp().get("certificate");
        final X509Certificate clientCert = PemUtils.getCertificateFromPem(clientCertPem);

        final String response = doMessage("/message", csr.getKeyPair(), clientCert, plainTextSend.getBytes());

        final byte[] decryptedResponse = decrypt(csr.getKeyPair().getPrivate(), clientCert, response);
        final CmsSign.Result result = validate(decryptedResponse);

        final String content = new String(result.getContent());
        if (logger.isInfoEnabled()) {
            logger.info(String.format("[testMessage] response content: %s", content));
            logger.info(String.format("[testMessage] response validated: %b", result.isVerifyOk()));
        }

        logger.info(String.format("[testMessage] %s", content));
        final PayloadDemoModel payloadDemoModel = PayloadDemoModel.deserialize(result.getContent());
        payloadDemoModel.getMapWithStrings().forEach((k, v)->{
            logger.info(String.format("[testMessage] %s: %s", k, v));
        });

        assertTrue(payloadDemoModel.getMapWithStrings().containsKey("foo"));
        assertTrue(payloadDemoModel.getMapWithStrings().containsValue("bar äöüÄÖÜß€"));
        assertTrue(result.isVerifyOk());
    }


    @Test
    void testRenew () throws Exception {
        final String username = "myUsername3";
        final String password = "myPassword3";

        // Build a valid certificate
        final Csr csr = testLib.genCsr("CN=cert3");
        final String pemCsr = PemUtils.encodeObjectToPEM(csr.getCsr());
        final LoginResponse loginResp = login(username, password, pemCsr);

        final String clientCertPem = loginResp.getResp().get("certificate");
        final X509Certificate clientCert = PemUtils.getCertificateFromPem(clientCertPem);

        final String response = doMessage("/renew", csr.getKeyPair(), clientCert, pemCsr.getBytes());

        final byte[] decryptedText = decrypt(csr.getKeyPair().getPrivate(), clientCert, response);
        final CmsSign.Result result = validate(decryptedText);

        final RenewModel resultMap = RenewModel.deserialize(result.getContent());

        final String newCertPEM = resultMap.getCertificate();
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
