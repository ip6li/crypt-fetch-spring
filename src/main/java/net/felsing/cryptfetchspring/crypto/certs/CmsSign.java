/*
 * Copyright (c) 2017 by Christian Felsing
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


import net.felsing.cryptfetchspring.crypto.config.ProviderLoader;
import net.felsing.cryptfetchspring.crypto.util.LogEngine;
import net.felsing.cryptfetchspring.crypto.util.PemUtils;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaCertStoreBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.*;
import java.util.*;


public final class CmsSign {
    private static final LogEngine logger = LogEngine.getLogger(CmsSign.class);

    static {
        Security.addProvider(ProviderLoader.getProvider());
    }

    public static class Result {
        private boolean verifyOk;
        private byte[] content;
        private List<X509Certificate> certificates;

        public boolean isVerifyOk() {
            return verifyOk;
        }

        public byte[] getContent() {
            return content;
        }

        public List<X509Certificate> getCertificates() {
            return certificates;
        }
    }


    private CMSSignedData signCms(boolean enveloped, KeyPair key, X509Certificate cert, byte[] unsignedData)
            throws CertificateEncodingException, OperatorCreationException, CMSException {

        String keyAlgo = key.getPrivate().getAlgorithm();
        String hashAlgo = "SHA256";
        String signatureAlgorithm;
        if ("EC".equalsIgnoreCase(keyAlgo)) {
            signatureAlgorithm = hashAlgo + "WITHECDSA";
        } else {
            signatureAlgorithm = hashAlgo + "WITH" + keyAlgo;
        }


        //String signatureAlgorithm = cert.getSigAlgName();
        //logger.info(String.format("signCms1: %s", signatureAlgorithm));
        if (signatureAlgorithm.matches(".*RSASSA-PSS")) { signatureAlgorithm = "SHA256withRSAandMGF1"; }
        logger.info(String.format("signCms2: %s", signatureAlgorithm));

        List<X509Certificate> certList = new ArrayList<>();

        CMSTypedData msg = new CMSProcessableByteArray(unsignedData);

        certList.add(cert);

        JcaCertStore certs = new JcaCertStore(certList);

        DigestCalculatorProvider digProvider = new JcaDigestCalculatorProviderBuilder()
                .setProvider(ProviderLoader.getProviderName())
                .build();

        JcaSignerInfoGeneratorBuilder signerInfoGeneratorBuilder =
                new JcaSignerInfoGeneratorBuilder(digProvider);

        ContentSigner signer = new JcaContentSignerBuilder(signatureAlgorithm)
                .setProvider(ProviderLoader.getProviderName())
                .build(key.getPrivate());

        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

        gen.addSignerInfoGenerator(signerInfoGeneratorBuilder.build(signer, cert));
        gen.addCertificates(certs);

        return gen.generate(msg,enveloped);
    }


    public CMSSignedData signCmsEnveloped(KeyPair key, X509Certificate cert, byte[] unsignedData)
            throws CertificateEncodingException, OperatorCreationException, CMSException {

        return signCms(true, key, cert, unsignedData);
    }


    public CMSSignedData signCmsDetached(KeyPair key, X509Certificate cert, byte[] unsignedData)
            throws CertificateEncodingException, OperatorCreationException, CMSException {

        return signCms(false, key, cert, unsignedData);
    }


    /**
         * Validates content and certificate chain
         *
         * @param signedData        Signed data
         * @param caCertificate     CA certificate
         * @return validation result, in case of success, also data and signers certificate
         */
    public Result verifyCmsSignature(CMSSignedData signedData, X509Certificate caCertificate) {
        final boolean[] verifyOk = {true};
        final Result result = new Result();

        try {
            Store<X509CertificateHolder> certificates = signedData.getCertificates();
            Collection<X509CertificateHolder> matches = certificates.getMatches(null);
            CMSTypedData signedContent = signedData.getSignedContent();

            byte[] content = (byte[]) signedContent.getContent();
            ArrayList<X509Certificate> trustStore = new ArrayList<>();
            trustStore.add(caCertificate);
            ArrayList<X509Certificate> chain = new ArrayList<>();
            matches.forEach(k -> {
                try {
                    X509Certificate l = new JcaX509CertificateConverter().setProvider(ProviderLoader.getProviderName()).getCertificate(k);
                    chain.add(l);
                } catch (Exception e) {
                    verifyOk[0] = false;
                    logger.warn(String.format("verifyCmsSignature: Cannot validate message: %s", e.getMessage()));
                }
            });
            result.content = content;
            result.certificates = chain;
            verifyOk[0] &= validateChain(trustStore, chain);
        } catch (Exception e) {
            verifyOk[0] = false;
            logger.warn(String.format("verifyCmsSignature: None of the certificates are validating message: %s", e.getMessage()));
        }

        result.verifyOk = verifyOk[0];

        return result;
    }


    /**
     * Validates signers certificates with trustStore CA certificates
     *
     * @param trustStore List of trusted CA certificates
     * @param signers    List of certificates cms signed with
     */
    private boolean validateChain(List<X509Certificate> trustStore, List<X509Certificate> signers) {
        Security.addProvider(ProviderLoader.getProvider());
        final boolean[] verifyOk = {true};

        try {
            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            ks.load(null, null);
            trustStore.forEach(k -> {
                try {
                    ks.setCertificateEntry(k.getSubjectDN().getName(), k);
                    logger.info(String.format("validateChain (trustStore)%n%s", PemUtils.encodeObjectToPEM(k)));
                } catch (Exception e) {
                    verifyOk[0] = false;
                    logger.warn(String.format("validateChain: Cannot add CA certificate to trustchain: %s", e.getMessage()));
                }
            });

            PKIXBuilderParameters params = new PKIXBuilderParameters(ks, new X509CertSelector());
            JcaCertStoreBuilder builder = new JcaCertStoreBuilder();
            signers.forEach(k -> {
                try {
                    logger.info(String.format("validateChain (cert)%n%s", PemUtils.encodeObjectToPEM(k)));
                    builder.addCertificate(new X509CertificateHolder(k.getEncoded()));
                } catch (CertificateEncodingException | IOException e) {
                    verifyOk[0] = false;
                    logger.warn(String.format("validateChain: Cannot add certificate to chain: %s", e.getMessage()));
                }
            });

            params.addCertStore(builder.build());
            params.setRevocationEnabled(false);
            params.getSigProvider();
            // ToDo: is this a Bouncy Castle problem? I don't know...
            //CertPathBuilder cpBuilder = CertPathBuilder.getInstance("PKIX", ProviderLoader.getProviderName());
            CertPathBuilder cpBuilder = CertPathBuilder.getInstance("PKIX");
            cpBuilder.build(params);
        } catch (Exception e) {
            verifyOk[0] = false;
            logger.warn(String.format("validateChain: Cannot validate certificate chain: %s", e.getMessage()));
        }

        return verifyOk[0];
    }

} // class
