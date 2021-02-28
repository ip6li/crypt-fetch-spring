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
import net.felsing.cryptfetchspring.crypto.config.ProviderLoader;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.slf4j.LoggerFactory;
import org.slf4j.Logger;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.*;
import java.util.*;


public final class Certificates {
    private static final Logger logger = LoggerFactory.getLogger(Certificates.class);


    private int validForDays = 365;
    private X509Certificate x509Certificate;
    private KeyPair keyPair;
    private final List<KeyPurposeId> extendedKeyUsages = new ArrayList<>();
    private String caIssuersUri;
    private String ocspResponderUrl;
    private boolean ocspCritical = true;


    public KeyPair getKeyPair() {

        return keyPair;
    }


    public X509Certificate getX509Certificate() {

        return x509Certificate;
    }


    public void addExtendedKeyUsage(KeyPurposeId keyPurposeId) {

        extendedKeyUsages.add(keyPurposeId);
    }


    private void setExtendedUsage(X509v3CertificateBuilder certificate) throws IOException {
        if (!extendedKeyUsages.isEmpty()) {
            KeyPurposeId[] keyPurposeIds = new KeyPurposeId[extendedKeyUsages.size()];
            extendedKeyUsages.toArray(keyPurposeIds);
            ExtendedKeyUsage usageEx = new ExtendedKeyUsage(keyPurposeIds);
            certificate.addExtension(
                    Extension.extendedKeyUsage,
                    false,
                    usageEx.getEncoded());
        }
    }


    private static Date calcValid(int days) {
        Calendar cal = Calendar.getInstance();
        cal.add(Calendar.DATE, days);
        return cal.getTime();
    }


    public void createSelfSignedCertificateRSA(String subjectDN, boolean pss)
            throws OperatorCreationException, CertificateException, IOException,
            NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {

        createSelfSignedCertificateRSA(subjectDN, 2048, pss);
    }


    public void createSelfSignedCertificateRSA(String subjectDN, Integer keyLength, boolean pss)
            throws OperatorCreationException, CertificateException, IOException,
            NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {

        Provider bcProvider = ProviderLoader.getProvider();
        Security.addProvider(bcProvider);

        KeyPair tmpKeyPair = KeyUtils.generateKeypair(Constants.KeyType.RSA, keyLength);

        Date startDate = new Date();
        Date endDate = calcValid(validForDays);
        X500Name dnName = new X500Name(subjectDN);

        byte[] id = new byte[20];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(id);
        BigInteger serial = new BigInteger(160, secureRandom);

        String signatureAlgorithm;
        if (pss) {
            signatureAlgorithm = "SHA384withRSAandMGF1";
        } else {
            signatureAlgorithm = "SHA256With" + tmpKeyPair.getPrivate().getAlgorithm();
        }
        ContentSigner contentSigner = new JcaContentSignerBuilder(signatureAlgorithm).build(tmpKeyPair.getPrivate());

        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                dnName, serial, startDate, endDate, dnName, tmpKeyPair.getPublic()
        );

        BasicConstraints basicConstraints = new BasicConstraints(true); // <-- true for CA, false for EndEntity
        certBuilder.addExtension(new ASN1ObjectIdentifier(Constants.oidSan), true, basicConstraints); // Basic Constraints is usually marked as critical.

        if (ocspResponderUrl != null && caIssuersUri != null) {
            setOcspAttributes(certBuilder);
        }

        setExtendedUsage(certBuilder);

        X509Certificate serverCertificate = new JcaX509CertificateConverter().setProvider(bcProvider).getCertificate(certBuilder.build(contentSigner));

        this.keyPair = tmpKeyPair;
        this.x509Certificate = serverCertificate;
    }


    public void createSelfSignedCertificateEC(String subjectDN)
            throws OperatorCreationException, CertificateException, IOException,
            NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {

        createSelfSignedCertificateEC(subjectDN, 256);
    }


    public void createSelfSignedCertificateEC(String subjectDN, Integer keyLength)
            throws OperatorCreationException, CertificateException, IOException,
            NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {

        Provider bcProvider = ProviderLoader.getProvider();
        Security.addProvider(bcProvider);

        KeyPair keypair = KeyUtils.generateKeypair(Constants.KeyType.EC, keyLength);

        X500Name subject = new X500Name(subjectDN);

        long now = System.currentTimeMillis();
        Date startDate = new Date(now);
        Date endDate = calcValid(validForDays);

        byte[] id = new byte[20];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(id);
        BigInteger serial = new BigInteger(160, secureRandom);

        JcaX509v3CertificateBuilder certificate = new JcaX509v3CertificateBuilder(
                subject,
                serial,
                startDate,
                endDate,
                subject,
                keypair.getPublic());

        certificate.addExtension(Extension.subjectKeyIdentifier, false, id);
        certificate.addExtension(Extension.authorityKeyIdentifier, false, id);
        BasicConstraints constraints = new BasicConstraints(true);
        certificate.addExtension(
                Extension.basicConstraints,
                true,
                constraints.getEncoded());
        KeyUsage usage = new KeyUsage(KeyUsage.keyCertSign | KeyUsage.digitalSignature);
        certificate.addExtension(Extension.keyUsage, false, usage.getEncoded());

        if (ocspResponderUrl != null && caIssuersUri != null) {
            setOcspAttributes(certificate);
        }

        setExtendedUsage(certificate);

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA")
                .build(keypair.getPrivate());
        X509CertificateHolder holder = certificate.build(signer);

        this.keyPair = keypair;
        this.x509Certificate = new JcaX509CertificateConverter().setProvider(bcProvider).getCertificate(holder);
    }


    private static void addIdentity (List<String> identities, ASN1InputStream decoder)
            throws IOException {
        ASN1Primitive encoded = decoder.readObject();
        String identity = ((DERUTF8String) encoded).getString();
        identities.add(identity);
    }


    private static void decodeSubjectAltName (List<?> item, List<String> identities) {
        ASN1InputStream decoder = null;
        try {
            if (item.toArray()[1] instanceof byte[])
                decoder = new ASN1InputStream((byte[]) item.toArray()[1]);
            else if (item.toArray()[1] instanceof String)
                identities.add((String) item.toArray()[1]);
            if (decoder == null) return;
            addIdentity(identities, decoder);
        } catch (Exception e) {
            logger.error("Error decoding subjectAltName {}", e.getLocalizedMessage(), e);
        }
    }


    public static List<String> getSubjectAlternativeNames(X509Certificate x509Certificate) {
        List<String> identities = new ArrayList<>();
        try {
            Collection<List<?>> altNames = x509Certificate.getSubjectAlternativeNames();
            for (List<?> item : altNames) {
                Integer type = (Integer) item.get(0);
                if (Arrays.stream(Constants.allowedSanTypes).anyMatch(type::equals)) {
                    decodeSubjectAltName(item, identities);
                } else {
                    logger.warn("Unknown SAN type: {}", type);
                }
            }
        } catch (NullPointerException ne) {
            // do nothing
        } catch (Exception e) {
            logger.warn(e.getMessage());
        }
        return identities;
    }


    public void setValidForDays(int validForDays) {

        this.validForDays = validForDays;
    }


    private void setOcspAttributes (JcaX509v3CertificateBuilder certBuilder) throws CertIOException {
            GeneralName ocspName = new GeneralName(GeneralName.uniformResourceIdentifier, ocspResponderUrl);
            GeneralName caIssuersName = new GeneralName(GeneralName.uniformResourceIdentifier, caIssuersUri);
            AccessDescription ocsp = new AccessDescription(AccessDescription.id_ad_ocsp, ocspName);
            AccessDescription caIssuers = new AccessDescription(AccessDescription.id_ad_caIssuers, caIssuersName);
            AuthorityInformationAccess authorityInformationAccess = new AuthorityInformationAccess(
                    new AccessDescription[]{ocsp, caIssuers});
            certBuilder.addExtension(Extension.authorityInfoAccess, ocspCritical, authorityInformationAccess);
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
