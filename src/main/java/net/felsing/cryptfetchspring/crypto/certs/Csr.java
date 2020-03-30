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

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.security.KeyPair;
import java.util.List;


public final class Csr {

    private KeyPair keyPair;
    private PKCS10CertificationRequest csr;


    /**
     * Creates a keypair and a PKCS#10 CSR
     * @param keyType :        RSA or EC
     * @param size :        Key size
     *                          RSA: should be >= 2048 for RSA
     *                          EC: should be >= 256 for EC
     * @param dn :          DN
     */
    public void createCsr(Certificates.KeyType keyType, int size, String dn, List<GeneralName> sanList) throws Exception {

        keyPair = Certificates.generateKeypair(keyType, size);

        PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(
                new X500Principal(dn), keyPair.getPublic());

        String alg = keyPair.getPrivate().getAlgorithm();
        if (alg.matches("EC.*")) {
            alg="ECDSA";
        }
        JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder("SHA256with" + alg);
        if (sanList!=null) {
            setSubjectAltNames(p10Builder, sanList);
        }
        ContentSigner contentSigner = csBuilder.build(keyPair.getPrivate());
        csr = p10Builder.build(contentSigner);
    }


    public void createCsr(Certificates.KeyType keyType, int size, String dn) throws Exception {

        createCsr(keyType, size, dn, null);
    }


    public void createCsr(Certificates.KeyType keyType, String dn) throws Exception {

        int size;

        switch (keyType) {
            case RSA: size=2048; break;
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

        return csr;
    }

} // class
