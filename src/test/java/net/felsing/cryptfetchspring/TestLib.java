package net.felsing.cryptfetchspring;

import net.felsing.cryptfetchspring.crypto.certs.CA;
import net.felsing.cryptfetchspring.crypto.certs.Certificates;
import net.felsing.cryptfetchspring.crypto.certs.Csr;
import net.felsing.cryptfetchspring.crypto.certs.Signer;
import net.felsing.cryptfetchspring.crypto.util.PemUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.security.cert.X509Certificate;
import java.util.HashMap;

public class TestLib {
    private static Logger logger = LogManager.getLogger(TestLib.class);

    private static CA ca;


    private TestLib () {
        try {
            ca = CryptInit.getInstance("./");
            ServerConfig.getInstance(ca, CryptInit.getServerCertificate(), CryptInit.getSignerCertificate());
        } catch (Exception e) {
            logger.error("BeforeAll failed");
            logger.error(e);
        }
    }

    public static TestLib getInstance () {

        return new TestLib();
    }


    public Csr genCsr (String dn) throws Exception {
        Csr request = new Csr();
        request.createCsr(Certificates.KeyType.RSA, 2048, "CN=".concat(dn));
        return request;
    }


    public HashMap<String, String> genClientCertificate (String cn) throws Exception {
        HashMap<String, String> certStore = new HashMap<>();
        Csr request = new Csr();

        String privateKey;
        String csr;
        String certificate;

        request.createCsr(Certificates.KeyType.RSA, 2048, "CN=".concat(cn));
        privateKey = PemUtils.encodeObjectToPEM(request.getKeyPair().getPrivate());
        csr = PemUtils.encodeObjectToPEM(request.getCsr());
        certStore.put("privateKey", privateKey);
        certStore.put("csr", csr);

        Signer signer = new Signer();
        signer.setValidTo(1);

        certificate = signer.signClient(csr, ca.getCaPrivateKeyPEM(), ca.getCaCertificatePEM());
        certStore.put("certificate", certificate);

        return certStore;
    }


    public X509Certificate getCaCertificate () {

        return ca.getCaX509Certificate();
    }

}
