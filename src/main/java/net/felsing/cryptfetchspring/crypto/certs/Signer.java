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


import net.felsing.cryptfetchspring.crypto.util.PemUtils;
import net.felsing.cryptfetchspring.crypto.config.Constants;
import net.felsing.cryptfetchspring.crypto.config.ProviderLoader;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.operator.*;
import org.bouncycastle.operator.bc.BcECContentSignerBuilder;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.slf4j.LoggerFactory;
import org.slf4j.Logger;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.List;


public final class Signer {
    private static final Logger logger = LoggerFactory.getLogger(Signer.class);

    static {
        Security.addProvider(ProviderLoader.getProvider());
    }

    private Date validFrom = new Date(System.currentTimeMillis());
    private final List<ASN1Encodable> sans = new ArrayList<>();
    private X500Name subject = null;
    private Date validTo;

    private enum modeEnum {CLIENT, SERVER}

    
    public Signer() {
        setValidTo(Constants.caDays);
    }


    public String signClient(String inputCSR, String privateKey, String caCertificate)
            throws OperatorCreationException,
            NoSuchAlgorithmException, IOException,
            NoSuchProviderException, CertificateException, InvalidKeySpecException {

        return sign(modeEnum.CLIENT, inputCSR, privateKey, caCertificate);
    }


    public String signServer(String inputCSR, String privateKey, String caCertificate)
            throws OperatorCreationException,
            NoSuchAlgorithmException, IOException,
            NoSuchProviderException, CertificateException, InvalidKeySpecException {

        return sign(modeEnum.SERVER, inputCSR, privateKey, caCertificate);
    }


    private String sign(modeEnum mode, String inputCSR, String privateKey, String caCertificate)
            throws NoSuchAlgorithmException,
            NoSuchProviderException, IOException,
            OperatorCreationException, java.security.cert.CertificateException, InvalidKeySpecException {

        PrivateKey caPrivate = null;

        try {
            caPrivate = extractKey(PemUtils.parseDERfromPEM(
                    privateKey.getBytes()),
                    "RSA"
            );
        } catch (Exception e) {
            logger.error(e.getMessage());
        }

        if (caPrivate == null) {
            try {
                caPrivate = extractKey(PemUtils.parseDERfromPEM(
                        privateKey.getBytes()),
                        "EC"
                );
            } catch (Exception e) {
                logger.error(String.format("Neither RSA nor EC key: %s", e.getMessage()));
            }
        }

        if (caPrivate == null) {
            throw new IOException("Private key not readable");
        }

        X509Certificate caCert = PemUtils.getCertificateFromPem(caCertificate);
        String issuer = new JcaX509CertificateHolder(caCert).getIssuer().toString();
        
        PKCS10CertificationRequest pk10Holder = new PKCS10CertificationRequest(
                PemUtils.parseDERfromPEM(inputCSR.getBytes())
        );
        
        PublicKey csrPublicKey;
        final String caPrivateKeyAlgorithm = caPrivate.getAlgorithm();
        final String csrKeyAlgorithm = pk10Holder.getSubjectPublicKeyInfo().getAlgorithm().getAlgorithm().getId();
        
        KeyFactory keyFactory = null;
        if (csrKeyAlgorithm.equals(Constants.keyAlgoOidEC)) {
            keyFactory = KeyFactory.getInstance("EC");
        } else if (csrKeyAlgorithm.equals(Constants.keyAlgoOidRSA)) {
            keyFactory = KeyFactory.getInstance("RSA");
        }
        if (keyFactory == null)
            throw new CertIOException("cannot find keyfactory");
        csrPublicKey = keyFactory.generatePublic(new X509EncodedKeySpec(pk10Holder.getSubjectPublicKeyInfo().getEncoded()));

        if (csrPublicKey == null) throw new CertIOException("CSR has no public key");
        AsymmetricKeyParameter asymmetricKeyParameter = PrivateKeyFactory.createKey(caPrivate.getEncoded());
        SubjectPublicKeyInfo keyInfo = SubjectPublicKeyInfo.getInstance(csrPublicKey.getEncoded());

        if (subject == null)
            subject = pk10Holder.getSubject();

        byte[] serialNoChars = {'0','1','2','3','4','5','6','7','8','9'};
        X509v3CertificateBuilder x509v3CertificateBuilder = new X509v3CertificateBuilder(
                new X500Name(issuer),
                new BigInteger(PemUtils.getRandom(serialNoChars, 8)),
                validFrom,
                validTo,
                subject,
                keyInfo);

        x509v3CertificateBuilder.addExtension(
                Extension.basicConstraints,
                false, new BasicConstraints(false)
        );

        JcaX509ExtensionUtils jcaX509ExtensionUtils = new JcaX509ExtensionUtils();
        SubjectKeyIdentifier subjectKeyIdentifier =
                jcaX509ExtensionUtils.createSubjectKeyIdentifier(pk10Holder.getSubjectPublicKeyInfo());
        x509v3CertificateBuilder.addExtension(
                Extension.subjectKeyIdentifier,
                false,
                subjectKeyIdentifier
        );
        
        jcaX509ExtensionUtils = new JcaX509ExtensionUtils();
        AuthorityKeyIdentifier authorityKeyIdentifier =
                jcaX509ExtensionUtils.createAuthorityKeyIdentifier(caCert.getPublicKey());
        x509v3CertificateBuilder.addExtension(
                Extension.authorityKeyIdentifier,
                false,
                authorityKeyIdentifier
        );

        switch (mode) {
            case CLIENT:
                setKeyUsageClient(x509v3CertificateBuilder);
                break;
            case SERVER:
                setKeyUsageServer(x509v3CertificateBuilder);
                break;
        }

        fillInto(x509v3CertificateBuilder);

        ContentSigner sigGen;

        AlgorithmIdentifier sigAlgId;
        AlgorithmIdentifier digAlgId;

        if (caPrivateKeyAlgorithm.matches("EC.*")) {
            sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find(Constants.SHA_256_WITH_ECDSA);
            digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);
            sigGen = new BcECContentSignerBuilder(sigAlgId, digAlgId).build(asymmetricKeyParameter);
        } else if (caPrivateKeyAlgorithm.matches("RSA")) {
            sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find(Constants.SHA_256_WITH_RSA);
            digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);
            sigGen = new BcRSAContentSignerBuilder(sigAlgId, digAlgId).build(asymmetricKeyParameter);
        } else {
            throw new IOException("Only EC or RSA are supported, requested: " + caPrivateKeyAlgorithm);
        }

        X509CertificateHolder holder = x509v3CertificateBuilder.build(sigGen);

        org.bouncycastle.asn1.x509.Certificate eeX509CertificateStructure = holder.toASN1Structure();

        CertificateFactory cf = CertificateFactory.getInstance("X.509", ProviderLoader.getProviderName());

        // Read Certificate
        InputStream is1 = new ByteArrayInputStream(eeX509CertificateStructure.getEncoded());
        X509Certificate theCert = (X509Certificate) cf.generateCertificate(is1);
        is1.close();

        return PemUtils.encodeObjectToPEM(theCert);
    }


    public void setValidFrom(int days) {
        Calendar cal = Calendar.getInstance();
        cal.add(Calendar.DATE, days);
        setValidFrom(cal);
    }
    
    
    private void setValidFrom(Calendar cal) {
        
        validFrom = cal.getTime();
    }
    
    
    public void setValidTo(int days) {
        Calendar cal = Calendar.getInstance();
        cal.add(Calendar.DATE, days);
        setValidTo(cal);
    }

    
    private void setValidTo(Calendar cal) {
    
        validTo = cal.getTime();
    }

    
    private void fillInto(X509v3CertificateBuilder certGen)
            throws CertIOException {
        if (!sans.isEmpty()) {
            ASN1Encodable[] encodables = sans.toArray(new ASN1Encodable[0]);
            certGen.addExtension(Extension.subjectAlternativeName, false,
                    new DERSequence(encodables));
        }


    }


    private void setKeyUsageClient(X509v3CertificateBuilder x509v3CertificateBuilder) throws CertIOException {

        KeyUsage usage = new KeyUsage(
                KeyUsage.digitalSignature |
                        KeyUsage.nonRepudiation |
                        KeyUsage.keyEncipherment |
                        KeyUsage.dataEncipherment
        );

        ASN1EncodableVector purposes = new ASN1EncodableVector();
        purposes.add(KeyPurposeId.id_kp_clientAuth);
        purposes.add(KeyPurposeId.id_kp_emailProtection);

        setKeyUsage(x509v3CertificateBuilder, usage, purposes);
    }


    private void setKeyUsageServer(X509v3CertificateBuilder x509v3CertificateBuilder) throws CertIOException {

        KeyUsage usage = new KeyUsage(
                KeyUsage.digitalSignature |
                        KeyUsage.nonRepudiation |
                        KeyUsage.keyEncipherment |
                        KeyUsage.dataEncipherment
        );

        ASN1EncodableVector purposes = new ASN1EncodableVector();
        purposes.add(KeyPurposeId.id_kp_serverAuth);
        purposes.add(KeyPurposeId.id_kp_clientAuth);

        setKeyUsage(x509v3CertificateBuilder, usage, purposes);
    }


    private void setKeyUsage(X509v3CertificateBuilder x509v3CertificateBuilder, KeyUsage keyUsage,
                             ASN1EncodableVector purposes) throws CertIOException {
        x509v3CertificateBuilder.addExtension(Extension.keyUsage, false, keyUsage);

        x509v3CertificateBuilder.addExtension(
                Extension.extendedKeyUsage, false,
                new DERSequence(purposes)
        );
    }


    public void addIpAddress(String ipAddress) {

        sans.add(new GeneralName(GeneralName.iPAddress, ipAddress));
    }

    
    public void addDomainName(String dnsName) {

        sans.add(new GeneralName(GeneralName.dNSName, dnsName));
    }

    
    public void addUri(String uri) {

        sans.add(new GeneralName(GeneralName.uniformResourceIdentifier, uri));
    }
    
    
    public void addRfc822Name(String rfc822name) {

        sans.add(new GeneralName(GeneralName.rfc822Name, rfc822name));
    }


    public void setSubject(String subject) {

        this.subject = new X500Name(subject);
    }


    private static PrivateKey extractKey(byte[] pkcs8key, String mode) throws GeneralSecurityException {
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(pkcs8key);
        KeyFactory keyFactory = KeyFactory.getInstance(mode);
        PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
        logger.trace(privateKey.getAlgorithm());
        return privateKey;
    }
    
} // class
