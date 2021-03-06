/*
 * Copyright (c) 2016. by Christian Felsing
 * This program is free software: you can redistribute it and/or modify
 *     it under the terms of the GNU Affero General Public License as published by
 *     the Free Software Foundation, either version 3 of the License, or
 *     (at your option) any later version.
 *
 *     This program is distributed in the hope that it will be useful,
 *     but WITHOUT ANY WARRANTY; without even the implied warranty of
 *     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *     GNU Affero General Public License for more details.
 *
 *     You should have received a copy of the GNU Affero General Public License
 *     along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

package net.felsing.cryptfetchspring.crypto.certs;

import net.felsing.cryptfetchspring.crypto.config.Constants;
import net.felsing.cryptfetchspring.crypto.util.LogEngine;
import net.felsing.cryptfetchspring.crypto.util.PemUtils;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.operator.OperatorCreationException;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;


public final class CA {
    private static final LogEngine logger = LogEngine.getLogger(CA.class);

    private KeyPair caKeyPair;
    private X509Certificate caX509Certificate;
    private String caIssuersUri;
    private String ocspResponderUrl;
    private boolean ocspCritical = true;


    public X509Certificate getCaX509Certificate() {

        return caX509Certificate;
    }


    public String getCaPrivateKeyPEM() throws IOException, CertificateEncodingException {

        return PemUtils.encodeObjectToPEM(caKeyPair.getPrivate());
    }


    public String getCaCertificatePEM() {

        try {
            return PemUtils.encodeObjectToPEM(caX509Certificate);
        } catch (CertificateEncodingException | IOException e) {
            logger.error(e.getMessage());
            return "";
        }
    }


    public void createCertificationAuthority(Constants.KeyType mode, String subjectDN, Integer validForDays)
            throws OperatorCreationException, CertificateException, IOException,
            NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {

        Certificates certificates = new Certificates();
        certificates.addExtendedKeyUsage(KeyPurposeId.anyExtendedKeyUsage);
        certificates.addExtendedKeyUsage(KeyPurposeId.id_kp_clientAuth);
        certificates.addExtendedKeyUsage(KeyPurposeId.id_kp_emailProtection);
        certificates.setValidForDays(validForDays);
        if (caIssuersUri != null && ocspResponderUrl != null) {
            certificates.setCaIssuersUri(caIssuersUri);
            certificates.setOcspResponderUrl(ocspResponderUrl);
            certificates.setOcspCritical(ocspCritical);
        }
        switch (mode) {
            case RSA:
                certificates.createSelfSignedCertificateRSA(subjectDN, false);
                break;
            case RSAPSS:
                certificates.createSelfSignedCertificateRSA(subjectDN, true);
                break;
            case EC:
                certificates.createSelfSignedCertificateEC(subjectDN);
                break;
            default:
                throw new IOException("unknown mode");
        }

        caKeyPair = certificates.getKeyPair();

        caX509Certificate = certificates.getX509Certificate();
    }

    public void loadCertificationAuthorityKeystore(String keystoreFile, String keystorePassword)
            throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException,
            UnrecoverableKeyException {
        KeyStore keyStore = KeyStoreUtils.loadKeystore(keystoreFile, keystorePassword);

        caKeyPair = KeyStoreUtils.getKeypairFromKeystore(keyStore, keystorePassword);
        caX509Certificate = KeyStoreUtils.getCertificateFromKeystore(keyStore, keystorePassword);
        logger.info(String.format("Using existing CA certificate %s", keystoreFile));
    }

    public void saveCertificationAuthorityKeystore(String keystoreFile, String keystorePassword)
            throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        String alias = caX509Certificate.getSubjectDN().getName();
        KeyStoreUtils.saveToKeystore(alias, caKeyPair, caX509Certificate, keystoreFile, keystorePassword);
    }


    public void setOcspCritical(boolean ocspCritical) {

        this.ocspCritical = ocspCritical;
    }


    public void setCaIssuersUri(String caIssuersUri) {

        this.caIssuersUri = caIssuersUri;
    }

    public void setOcspResponderUrl(String ocspResponderUrl) {

        this.ocspResponderUrl = ocspResponderUrl;
    }

} // class
