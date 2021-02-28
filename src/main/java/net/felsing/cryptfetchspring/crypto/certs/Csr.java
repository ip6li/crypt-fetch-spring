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
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateEncodingException;
import java.util.List;


public final class Csr {
    private static final LogEngine logger = LogEngine.getLogger(Csr.class);
    private KeyPair keyPair;
    private PKCS10CertificationRequest pkcs10CertificationRequest;


    /**
     * Creates a keypair and a PKCS#10 CSR
     * @param keyType :        RSA or EC
     * @param size :        Key size
     *                          RSA: should be >= 2048 for RSA
     *                          EC: should be >= 256 for EC
     * @param dn :          DN
     */
    public void createCsr(Constants.KeyType keyType, int size, String dn, List<GeneralName> sanList)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException,
            IOException, OperatorCreationException {

        keyPair = KeyUtils.generateKeypair(keyType, size);

        PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(
                new X500Principal(dn), keyPair.getPublic());

        String alg;
        switch (keyType) {
            case EC: alg=String.format("SHA256with%s",KeyUtils.EC); break;
            case RSA: alg=String.format("SHA256with%s",KeyUtils.RSA); break;
            case RSAPSS: alg="SHA384withRSAandMGF1"; break;
            default: throw new IOException(String.format("Unknown keytype: %s", keyType));
        }

        JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder(alg);
        if (sanList!=null) {
            setSubjectAltNames(p10Builder, sanList);
        }
        ContentSigner contentSigner = csBuilder.build(keyPair.getPrivate());
        pkcs10CertificationRequest = p10Builder.build(contentSigner);
    }


    public void createCsr(Constants.KeyType keyType, int size, String dn)
            throws NoSuchAlgorithmException, OperatorCreationException, InvalidAlgorithmParameterException, NoSuchProviderException, IOException {

        createCsr(keyType, size, dn, null);
    }


    public void createCsr(Constants.KeyType keyType, String dn)
            throws IOException, OperatorCreationException, InvalidAlgorithmParameterException,
            NoSuchAlgorithmException, NoSuchProviderException {

        int size;

        switch (keyType) {
            case RSA:
            case RSAPSS:
                size=2048; break;
            case EC: size=256; break;
            default: throw new IOException("Unknown key type: " + keyType.toString());
        }

        createCsr(keyType, size, dn);
    }


    private void setSubjectAltNames(PKCS10CertificationRequestBuilder builder, List<GeneralName> sanList)
            throws IOException {

        ExtensionsGenerator extGen = new ExtensionsGenerator();

        GeneralNames subjectAltNames = new GeneralNames(sanList.toArray(new GeneralName[]{}));
        extGen.addExtension(Extension.subjectAlternativeName, false, subjectAltNames);
        builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extGen.generate());
    }


    public KeyPair getKeyPair() {

        return keyPair;
    }


    public PKCS10CertificationRequest getCsr () {

        return pkcs10CertificationRequest;
    }


    public String getCsrPEM ()
            throws IOException, CertificateEncodingException {

        return PemUtils.encodeObjectToPEM(pkcs10CertificationRequest);
    }

} // class
