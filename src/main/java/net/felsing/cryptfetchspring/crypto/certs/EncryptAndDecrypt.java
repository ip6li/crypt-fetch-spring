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
import net.felsing.cryptfetchspring.crypto.util.PemUtils;
import net.felsing.cryptfetchspring.crypto.util.Random;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.bc.BcCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.*;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.operator.jcajce.JcaAlgorithmParametersConverter;
import org.slf4j.LoggerFactory;
import org.slf4j.Logger;
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
    private static final Logger logger = LoggerFactory.getLogger(EncryptAndDecrypt.class);

    private static final String MD_NAME = "SHA-512";
    private static final String MDG_NAME = "MGF1";


    public byte[] decrypt(PrivateKey privateKey, X509Certificate encryptionCert, String encryptedDataPEM)
            throws IOException, CMSException {

        return decrypt(privateKey, encryptionCert, PemUtils.parseDERfromPEM(encryptedDataPEM.getBytes()));
    }

    /**
     * decrypts data
     *
     * @param privateKey       Recipients private key
     * @param encryptionCert   Recipients certificate
     * @param encryptedDataDER Encrypted data in PEM format
     * @return Plain text
     * @throws IOException  in case of data failures
     * @throws CMSException in case of decryption failures
     */
    public byte[] decrypt(
            PrivateKey privateKey, X509Certificate encryptionCert, byte[] encryptedDataDER)
            throws IOException, CMSException {

        if (encryptedDataDER == null) {
            throw new IOException("encryptedData is null");
        }

        String alg = privateKey.getAlgorithm();
        if (alg.matches("EC.*")) {
            return decryptEC(privateKey, encryptionCert, encryptedDataDER);
        } else {
            return decryptRSA(privateKey, encryptedDataDER);
        }
    }


    private byte[] decryptRSA(PrivateKey privateKey, byte[] encryptedDataDER)
            throws IOException, CMSException {
        CMSEnvelopedDataParser parser = new CMSEnvelopedDataParser(encryptedDataDER);
        RecipientInformation recInfo = getSingleRecipient(parser);
        Recipient recipient = new JceKeyTransEnvelopedRecipient(privateKey);
        return recInfo.getContent(recipient);
    }


    private byte[] decryptEC(
            PrivateKey privateKey, X509Certificate encryptionCert, byte[] encryptedDataDER
    ) throws CMSException {

        CMSEnvelopedData envelopedData = new CMSEnvelopedData(encryptedDataDER);
        RecipientInformationStore recipients = envelopedData.getRecipientInfos();
        RecipientId rid = new JceKeyAgreeRecipientId(encryptionCert);
        RecipientInformation recipient = recipients.get(rid);
        return recipient.getContent(new JceKeyAgreeEnvelopedRecipient(privateKey).setProvider("BC"));
    }


    public String encryptPem(PrivateKey privateKeySender, X509Certificate certSender,
                             X509Certificate certRcpt, byte[] plainText)
            throws IOException, CMSException, CertificateException, InvalidAlgorithmParameterException {

        return PemUtils.encodeObjectToPEM(encrypt(privateKeySender, certSender, certRcpt, plainText));
    }


    public String encryptPem(X509Certificate certRcpt, byte[] plainText)
            throws IOException, CMSException, CertificateException, InvalidAlgorithmParameterException {

        return encryptPem(null, null, certRcpt, plainText);
    }


    public CMSEnvelopedData encrypt(PrivateKey privateKeySender, X509Certificate certSender,
                                    X509Certificate certRcpt, byte[] plainText)
            throws IOException, CMSException, CertificateException, InvalidAlgorithmParameterException {

        if (plainText == null) {
            throw new IOException("plaintext is null");
        }

        String certAlgName = certRcpt.getPublicKey().getAlgorithm();

        if (certAlgName.matches("EC.*")) {
            return encryptEC(privateKeySender, certSender, certRcpt, plainText);
        } else {
            return encryptRSA(certRcpt, plainText);
        }
    }


    private CMSEnvelopedData encryptRSA(X509Certificate cert, byte[] plainText)
            throws CertificateEncodingException, CMSException,
            InvalidAlgorithmParameterException {

        JcaAlgorithmParametersConverter paramsConverter = new JcaAlgorithmParametersConverter();
        OAEPParameterSpec oaepSpec = new OAEPParameterSpec(
                MD_NAME,
                MDG_NAME,
                new MGF1ParameterSpec(MD_NAME),
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

        if (logger.isDebugEnabled()) {
            logger.debug(String.format("encrypt: %s", cert.getSigAlgName()));
        }
        ASN1ObjectIdentifier cmsAlgorithm;
        cmsAlgorithm = CMSAlgorithm.AES256_CBC; // AES256_GCM does not work with PKI.js
        OutputEncryptor encryptor = new JceCMSContentEncryptorBuilder(
                cmsAlgorithm).
                setProvider(
                        ProviderLoader.getProviderName()
                ).build();

        return gen.generate(new CMSProcessableByteArray(plainText), encryptor);
    }


    private void addUKM(JceKeyAgreeRecipientInfoGenerator rig) {
        SecureRandom random = Random.getSecureRandom();

        byte[] ukm = new byte[64];
        random.nextBytes(ukm);
        rig.setUserKeyingMaterial(ukm);
    }


    private void setOriginatorInfo(CMSEnvelopedDataGenerator gen, X509Certificate cert)
            throws CertificateEncodingException, IOException {
        assert (cert!=null);
        X509CertificateHolder origCert = new X509CertificateHolder(
                cert.getEncoded()
        );
        gen.setOriginatorInfo(new OriginatorInfoGenerator(origCert).generate());
    }


    private CMSEnvelopedData encryptEC(PrivateKey privateKeySender, X509Certificate certSender, X509Certificate certRcpt, byte[] plainText)
            throws CMSException, IOException, CertificateException {

        CMSEnvelopedDataGenerator gen = new CMSEnvelopedDataGenerator();
        assert (certSender!=null);
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

        return gen.generate(new CMSProcessableByteArray(plainText), encryptor);
    }


    private static RecipientInformation getSingleRecipient(CMSEnvelopedDataParser parser) throws IOException {
        Collection<RecipientInformation> recInfos = parser.getRecipientInfos().getRecipients();
        Iterator<RecipientInformation> recipientIterator = recInfos.iterator();
        if (!recipientIterator.hasNext()) {
            throw new IOException("Could not find recipient");
        }
        return recipientIterator.next();
    }

} // class
