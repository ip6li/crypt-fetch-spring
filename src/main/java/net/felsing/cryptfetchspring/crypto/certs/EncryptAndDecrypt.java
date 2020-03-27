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
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.bc.BcCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.*;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.operator.jcajce.JcaAlgorithmParametersConverter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.MGF1ParameterSpec;
import java.util.Collection;
import java.util.Iterator;


public final class EncryptAndDecrypt {
    private static Logger logger = LogManager.getLogger(EncryptAndDecrypt.class);

    private static final String mdName = "SHA-512";
    private static final String mdgName = "MGF1";


    /**
     * decrypts data
     *
     * @param privateKey            Recipients private key
     * @param encryptionCert        Recipients certificate
     * @param encryptedDataPEM      Encrypted data in PEM format
     * @return                      Plain text
     * @throws IOException          in case of data failures
     * @throws CMSException         in case of decryption failures
     */
    public byte[] decrypt(
            PrivateKey privateKey, X509Certificate encryptionCert, byte[] encryptedDataPEM)
            throws IOException, CMSException {

        if (encryptedDataPEM==null) {
            throw new IOException("encryptedData is null");
        }

        String alg = privateKey.getAlgorithm();
        if (alg.matches("EC.*")) {
            return decryptEC(privateKey, encryptionCert, encryptedDataPEM);
        } else {
            return decryptRSA(privateKey, encryptedDataPEM);
        }
    }


    private byte[] decryptRSA(PrivateKey privateKey, byte[] encryptedDataPEM)
            throws IOException, CMSException {
        CMSEnvelopedDataParser parser = new CMSEnvelopedDataParser(encryptedDataPEM);
        RecipientInformation recInfo = getSingleRecipient(parser);
        Recipient recipient = new JceKeyTransEnvelopedRecipient(privateKey);
        return recInfo.getContent(recipient);
    }


    private byte[] decryptEC(
            PrivateKey privateKey, X509Certificate encryptionCert, byte[] encryptedDataPEM
    ) throws CMSException {

        CMSEnvelopedData envelopedData = new CMSEnvelopedData(encryptedDataPEM);
        RecipientInformationStore recipients = envelopedData.getRecipientInfos();
        RecipientId rid = new JceKeyAgreeRecipientId(encryptionCert);
        RecipientInformation recipient = recipients.get(rid);
        return recipient.getContent(new JceKeyAgreeEnvelopedRecipient(privateKey).setProvider("BC"));
    }


    public byte[] encrypt(PrivateKey privateKeySender, X509Certificate certSender,
                          X509Certificate certRcpt, byte[] plainText)
            throws IOException, CMSException, CertificateException, InvalidAlgorithmParameterException {

        if (plainText==null) {
            throw new IOException("plaintext is null");
        }

        String certAlgName = certRcpt.getPublicKey().getAlgorithm();

        if (certAlgName.matches("EC.*")) {
            return encryptEC(privateKeySender, certSender, certRcpt, plainText);
        } else {
            return encryptRSA(certRcpt, plainText);
        }
    }


    private byte[] encryptRSA(X509Certificate cert, byte[] plainText)
            throws CertificateEncodingException, CMSException, IOException,
            InvalidAlgorithmParameterException {

        JcaAlgorithmParametersConverter paramsConverter = new JcaAlgorithmParametersConverter();
        OAEPParameterSpec oaepSpec = new OAEPParameterSpec(
                mdName,
                mdgName,
                new MGF1ParameterSpec(mdName),
                PSource.PSpecified.DEFAULT
        );

        AlgorithmIdentifier oaepAlgId = paramsConverter.getAlgorithmIdentifier(
                PKCSObjectIdentifiers.id_RSAES_OAEP,
                oaepSpec
        );

        CMSEnvelopedDataGenerator gen = new CMSEnvelopedDataGenerator();
        gen.addRecipientInfoGenerator(
                new JceKeyTransRecipientInfoGenerator(
                        cert,
                        oaepAlgId).setProvider(ProviderLoader.getProviderName()
                )
        );

        logger.debug("encrypt: " + cert.getSigAlgName());

        ASN1ObjectIdentifier cmsAlgorithm;
        cmsAlgorithm = CMSAlgorithm.AES256_CBC; // AES256_GCM does not work with PKI.js
        OutputEncryptor encryptor = new JceCMSContentEncryptorBuilder(
                cmsAlgorithm).
                setProvider(
                        ProviderLoader.getProviderName()
                ).build();

        CMSEnvelopedData cmsEnvelopedData = gen.generate(new CMSProcessableByteArray(plainText), encryptor);

        return cmsEnvelopedData.getEncoded();
    }


    private void addUKM(JceKeyAgreeRecipientInfoGenerator rig) {
        SecureRandom random = new SecureRandom();

        byte[] ukm = new byte[64];
        random.nextBytes(ukm);
        rig.setUserKeyingMaterial(ukm);
    }


    private void setOriginatorInfo(CMSEnvelopedDataGenerator gen, X509Certificate cert)
            throws CertificateEncodingException, IOException {
        X509CertificateHolder origCert = new X509CertificateHolder(
                cert.getEncoded()
        );
        gen.setOriginatorInfo(new OriginatorInfoGenerator(origCert).generate());
    }


    private byte[] encryptEC(PrivateKey privateKeySender, X509Certificate certSender, X509Certificate certRcpt, byte[] plainText)
            throws CMSException, IOException, CertificateException {

        CMSEnvelopedDataGenerator gen = new CMSEnvelopedDataGenerator();

        JceKeyAgreeRecipientInfoGenerator rig = new JceKeyAgreeRecipientInfoGenerator(
                CMSAlgorithm.ECDH_SHA512KDF,
                privateKeySender,
                certSender.getPublicKey(),
                CMSAlgorithm.AES256_WRAP
        );

        rig.setProvider(ProviderLoader.getProviderName());
        rig.addRecipient(certRcpt);
        addUKM(rig);
        gen.addRecipientInfoGenerator(rig);
        if (Constants.enableOriginatorInfo)
            setOriginatorInfo(gen, certSender);

        OutputEncryptor encryptor =
                new BcCMSContentEncryptorBuilder(CMSAlgorithm.AES256_CBC).build();

        CMSEnvelopedData cmsEnvelopedData = gen.generate(new CMSProcessableByteArray(plainText), encryptor);

        return cmsEnvelopedData.getEncoded();
    }


    private static RecipientInformation getSingleRecipient(CMSEnvelopedDataParser parser) {
        Collection recInfos = parser.getRecipientInfos().getRecipients();
        Iterator recipientIterator = recInfos.iterator();
        if (!recipientIterator.hasNext()) {
            throw new RuntimeException("Could not find recipient");
        }
        return (RecipientInformation) recipientIterator.next();
    }


} // class
