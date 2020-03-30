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
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.*;


public final class Certificates {
    private static Logger logger = LogManager.getLogger(Certificates.class);

    public enum KeyType { RSA, EC }

    private static final int validDefault = 365;

    private X509Certificate x509Certificate;
    private KeyPair keyPair;
    private final List<KeyPurposeId> extendedKeyUsages= new ArrayList<>();



    public KeyPair getKeyPair () {

        return keyPair;
    }


    public Certificate getCertificate () {

        return x509Certificate;
    }


    public X509Certificate getX509Certificate() {

        return x509Certificate;
    }


    /**
     *
     * @param keyType "RSA" or "EC"
     * @throws NoSuchProviderException from KeyPairGenerator
     * @throws NoSuchAlgorithmException from KeyPairGenerator
     */
    static KeyPair generateKeypair(KeyType keyType, int size)
            throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        // generate a key pair

        switch (keyType) {
            case RSA:
                KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", ProviderLoader.getProviderName());
                keyPairGenerator.initialize(size, new SecureRandom());
                return keyPairGenerator.generateKeyPair();
            case EC:
                KeyPairGenerator kpgen = KeyPairGenerator.getInstance("ECDSA", ProviderLoader.getProviderName());
                ECGenParameterSpec ec = new ECGenParameterSpec("prime256v1");
                kpgen.initialize(ec, new SecureRandom());
                return kpgen.generateKeyPair();
        }
        throw new NoSuchProviderException("Algorithm not implemented: " + keyType.toString());
    }


    public void addExtendedKeyUsage(KeyPurposeId keyPurposeId) {

        extendedKeyUsages.add(keyPurposeId);
    }


    private void setExtendedUsage (X509v3CertificateBuilder certificate) throws IOException {
        if (extendedKeyUsages.size()>0) {

            KeyPurposeId[] keyPurposeIds = new KeyPurposeId[extendedKeyUsages.size()];
            extendedKeyUsages.toArray(keyPurposeIds);
            ExtendedKeyUsage usageEx = new ExtendedKeyUsage(keyPurposeIds);
            certificate.addExtension(
                    Extension.extendedKeyUsage,
                    false,
                    usageEx.getEncoded());
        }
    }


    private static Date calcValid (int days) {
        Calendar cal = Calendar.getInstance();
        cal.add(Calendar.DATE, days);
        return cal.getTime();
    }


    public void createSelfSignedCertificateRSA(String subjectDN, Integer validForDays)
            throws OperatorCreationException, CertificateException, IOException,
            NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {

        Provider bcProvider = ProviderLoader.getProvider();
        Security.addProvider(bcProvider);

        KeyPair keyPair = generateKeypair(KeyType.RSA, 2048);

        Date startDate = new Date();
        Date endDate;
        if (validForDays==null) {
            endDate = calcValid(validDefault);
        } else {
            endDate = calcValid(validForDays);
        }

        X500Name dnName = new X500Name(subjectDN);

        byte[] id = new byte[20];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(id);
        BigInteger serial = new BigInteger(160, secureRandom);

        String signatureAlgorithm = "SHA256With" + keyPair.getPrivate().getAlgorithm();

        ContentSigner contentSigner = new JcaContentSignerBuilder(signatureAlgorithm).build(keyPair.getPrivate());

        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                dnName, serial, startDate, endDate, dnName, keyPair.getPublic()
        );

        BasicConstraints basicConstraints = new BasicConstraints(true); // <-- true for CA, false for EndEntity
        certBuilder.addExtension(new ASN1ObjectIdentifier(Constants.oidSan), true, basicConstraints); // Basic Constraints is usually marked as critical.

        setExtendedUsage(certBuilder);

        X509Certificate serverCertificate = new JcaX509CertificateConverter().setProvider(bcProvider).getCertificate(certBuilder.build(contentSigner));

        this.keyPair = keyPair;
        this.x509Certificate = serverCertificate;
    }


    public void createSelfSignedCertificateEC(String subjectDN, Integer validForDays)
            throws OperatorCreationException, CertificateException, IOException,
            NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {

        Provider bcProvider = ProviderLoader.getProvider();
        Security.addProvider(bcProvider);

        KeyPair keypair = generateKeypair(KeyType.EC, 256);

        X500Name subject = new X500Name(subjectDN);

        long now = System.currentTimeMillis();
        Date startDate = new Date(now);
        Date endDate;
        if (validForDays==null) {
            endDate = calcValid(validDefault);
        } else {
            endDate = calcValid(validForDays);
        }

        byte[] id = new byte[20];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(id);
        BigInteger serial = new BigInteger(160, secureRandom);

        X509v3CertificateBuilder certificate = new JcaX509v3CertificateBuilder(
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

        setExtendedUsage(certificate);

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA")
                .build(keypair.getPrivate());
        X509CertificateHolder holder = certificate.build(signer);

        this.keyPair = keypair;
        this.x509Certificate = new JcaX509CertificateConverter().setProvider(bcProvider).getCertificate(holder);
    }


    public static List<String> getSubjectAlternativeNames(X509Certificate x509Certificate) {
        List<String> identities = new ArrayList<>();
        try {
            Collection<List<?>> altNames = x509Certificate.getSubjectAlternativeNames();
            for (List<?> item : altNames) {
                Integer type = (Integer) item.get(0);
                if (Arrays.stream(Constants.allowedSanTypes).anyMatch(type::equals)) {
                    try {
                        ASN1InputStream decoder = null;
                        if (item.toArray()[1] instanceof byte[])
                            decoder = new ASN1InputStream((byte[]) item.toArray()[1]);
                        else if (item.toArray()[1] instanceof String)
                            identities.add((String) item.toArray()[1]);
                        if (decoder == null) continue;
                        ASN1Primitive encoded = decoder.readObject();
                        String identity = ((DERUTF8String) encoded).getString();
                        identities.add(identity);
                    } catch (Exception e) {
                        logger.error("Error decoding subjectAltName" + e.getLocalizedMessage(), e);
                    }
                } else {
                    logger.warn("Unknown SAN type: " + type);
                }
            }
        } catch (NullPointerException ne) {
            return null;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return identities;
    }

} // class
