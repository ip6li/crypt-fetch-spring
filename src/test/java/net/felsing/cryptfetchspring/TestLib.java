package net.felsing.cryptfetchspring;

import net.felsing.cryptfetchspring.crypto.certs.CA;
import net.felsing.cryptfetchspring.crypto.certs.Csr;
import net.felsing.cryptfetchspring.crypto.certs.Signer;
import net.felsing.cryptfetchspring.crypto.config.Configuration;
import net.felsing.cryptfetchspring.crypto.config.Constants;
import net.felsing.cryptfetchspring.crypto.util.PemUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.security.cert.X509Certificate;
import java.util.HashMap;


public class TestLib {
    private static final Logger logger = LoggerFactory.getLogger(TestLib.class);
    public static final String pkiPath = "/tmp/pki";

    private static CA ca;
    private static TestLib testLib;
    private final Configuration config;

    private TestLib(String caRootPath) throws Exception {
        logger.debug("TestLib initialized");
        ca = CryptInit.getInstance(caRootPath);
        logger.info(String.format("caRootPath: %s", caRootPath));
        ca.setOcspCritical(false);
        ServerConfig.getInstance(ca, CryptInit.getServerCertificate());
        config = new Configuration();
    }


    public static TestLib getInstance(String caRootPath) throws Exception {

        if (testLib == null) {
            testLib = new TestLib(caRootPath);
        }

        return testLib;
    }


    public Csr genCsr(String dn) throws Exception {
        Csr request = new Csr();
        request.createCsr(Constants.KeyType.RSA, "CN=".concat(dn));
        return request;
    }


    public HashMap<String, String> genClientCertificate(String cn) throws Exception {
        HashMap<String, String> certStore = new HashMap<>();
        Csr request = new Csr();

        String privateKey;
        String csr;
        String certificate;

        request.createCsr(Constants.KeyType.RSA, "CN=".concat(cn));
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

}
