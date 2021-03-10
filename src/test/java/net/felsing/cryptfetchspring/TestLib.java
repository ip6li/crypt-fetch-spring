package net.felsing.cryptfetchspring;

import net.felsing.cryptfetchspring.crypto.certs.CA;
import net.felsing.cryptfetchspring.crypto.certs.Csr;
import net.felsing.cryptfetchspring.crypto.certs.Signer;
import net.felsing.cryptfetchspring.crypto.config.ClientConfig;
import net.felsing.cryptfetchspring.crypto.config.ClientConfigModel;
import net.felsing.cryptfetchspring.crypto.config.Configuration;
import net.felsing.cryptfetchspring.crypto.config.Constants;
import net.felsing.cryptfetchspring.crypto.util.LogEngine;
import net.felsing.cryptfetchspring.crypto.util.PemUtils;
import org.bouncycastle.operator.OperatorCreationException;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;


public class TestLib {
    private static final LogEngine logger = LogEngine.getLogger(TestLib.class);
    public static final String pkiPath = "/tmp/pki";

    private static CA ca;
    private static TestLib testLib;
    private final Configuration config;

    private TestLib(String caRootPath)
            throws IOException, CertificateException, NoSuchAlgorithmException,
            UnrecoverableKeyException, InvalidAlgorithmParameterException,
            URISyntaxException, NoSuchProviderException, OperatorCreationException,
            KeyStoreException, InvalidKeySpecException {
        logger.debug("TestLib initialized");
        ca = CryptInit.getInstance(caRootPath);
        logger.info(String.format("caRootPath: %s", caRootPath));
        ca.setOcspCritical(false);
        ClientConfig.getInstance(ca, CryptInit.getServerCertificate());
        config = new Configuration();
    }


    public static TestLib getInstance(String caRootPath)
            throws IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException,
            KeyStoreException, InvalidAlgorithmParameterException, NoSuchProviderException,
            OperatorCreationException, URISyntaxException, InvalidKeySpecException {

        if (testLib == null) {
            testLib = new TestLib(caRootPath);
        }

        return testLib;
    }


    public Csr genCsr(Constants.KeyType mode, String dn)
            throws OperatorCreationException, InvalidAlgorithmParameterException,
            NoSuchAlgorithmException, NoSuchProviderException, IOException {
        Csr request = new Csr();
        request.createCsr(mode, "CN=".concat(dn));
        return request;
    }


    public HashMap<String, String> genClientCertificate(String cn)
            throws OperatorCreationException, InvalidAlgorithmParameterException, NoSuchAlgorithmException,
            NoSuchProviderException, IOException, CertificateException, InvalidKeySpecException {
        HashMap<String, String> certStore = new HashMap<>();
        Csr request = new Csr();

        String privateKey;
        String csr;
        String certificate;

        request.createCsr(
                Constants.KeyType.valueOf(new Configuration().getConfig().getProperty("keyMode")),
                "CN=".concat(cn)
        );
        privateKey = PemUtils.encodeObjectToPEM(request.getKeyPair().getPrivate());
        csr = PemUtils.encodeObjectToPEM(request.getCsr());
        certStore.put("privateKey", privateKey);
        certStore.put("csr", csr);

        Signer signer = new Signer();
        int days = Integer.parseInt(config.getConfig().getProperty("certificate.days"));
        signer.setValidTo(days);

        certificate = signer.signClient(csr, ca.getCaPrivateKeyPEM(), ca.getCaCertificatePEM());
        certStore.put("certificate", certificate);

        return certStore;
    }


    public static CA getCa() {

        return ca;
    }

    public static X509Certificate getCaCertificate() {

        return ca.getCaX509Certificate();
    }

    public static boolean deleteDirectory(File dir) {
        File[] allContents = dir.listFiles();
        if (allContents != null) {
            for (File file : allContents) {
                deleteDirectory(file);
            }
        }
        return dir.delete();
    }

    public static ClientConfigModel createDefaultConfig() throws IOException {
        String json = "{\n" +
                "  \"config\": {\n" +
                "    \"same_enc_sign_cert\": true,\n" +
                "    \"keyAlg\": {\n" +
                "      \"hash\": \"SHA-256\",\n" +
                "      \"sign\": \"RSASSA-PKCS1-V1_5\",\n" +
                "      \"modulusLength\": 2048\n" +
                "    },\n" +
                "    \"encAlg\": {\n" +
                "      \"name\": \"AES-CBC\",\n" +
                "      \"length\": 256\n" +
                "    },\n" +
                "    \"remotekeystore\": {},\n" +
                "    \"authURL\": \"http://127.0.0.1:8080/login\",\n" +
                "    \"messageURL\": \"http://127.0.0.1:8080/message\",\n" +
                "    \"renewURL\": \"http://127.0.0.1:8080/renew\"\n" +
                "  }\n" +
                "}";
        InputStream jsonStream = new ByteArrayInputStream(json.getBytes());
        return ClientConfigModel.deserialize(jsonStream);
    }

}
