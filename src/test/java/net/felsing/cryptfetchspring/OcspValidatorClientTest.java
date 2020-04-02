package net.felsing.cryptfetchspring;

import net.felsing.cryptfetchspring.crypto.certs.CA;
import net.felsing.cryptfetchspring.crypto.certs.Certificates;
import net.felsing.cryptfetchspring.crypto.certs.Csr;
import net.felsing.cryptfetchspring.crypto.certs.Signer;
import net.felsing.cryptfetchspring.crypto.ocsp.OcspValidatorClient;
import net.felsing.cryptfetchspring.crypto.util.PemUtils;
import org.bouncycastle.asn1.x509.Extension;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.*;


class OcspValidatorClientTest {

    private static CA ca;
    private static Signer signer;
    private static X509Certificate testSubjectCert;
    private static KeyPair testSubjectKeyPair;


    @BeforeAll
    public static void init() throws Exception {
        ca = new CA();
        ca.createCertificationAuthority(
                Certificates.KeyType.RSA,
                "CN=Test CA for OCSP Test",
                365,
                "http://localhost:8080/ocsp"
        );

        System.out.println(ca.getCaCertificatePEM());
        signer = new Signer();

        Csr csr = new Csr();
        csr.createCsr(Certificates.KeyType.RSA, "CN=Test Certificate");
        testSubjectKeyPair = csr.getKeyPair();

        signer.setSubject(csr.getCsr().getSubject().toString());
        String certPEM = signer.signServer(
                PemUtils.encodeObjectToPEM(csr),
                ca.getCaPrivateKeyPEM(),
                ca.getCaCertificatePEM()
        );
        testSubjectCert = PemUtils.getCertificateFromPem(certPEM);
    }


    @Test
    void testOcsp() throws Exception {
        OcspValidatorClient ocspValidatorClient = OcspValidatorClient.getInstance();
        ocspValidatorClient.validate(testSubjectCert, ca.getCaX509Certificate());
    }

}
