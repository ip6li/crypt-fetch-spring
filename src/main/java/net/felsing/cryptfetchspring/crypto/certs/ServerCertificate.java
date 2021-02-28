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
import org.bouncycastle.operator.OperatorCreationException;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;


public final class ServerCertificate {
    private static final LogEngine logger = LogEngine.getLogger(ServerCertificate.class);
    private KeyPair keyPair;
    private X509Certificate x509ServerCertificate;


    public KeyPair getServerKeyPair() {

        return keyPair;
    }

    
    public X509Certificate getServerCertificate () {

        return x509ServerCertificate;
    }

    public String getServerCertificatePEM () throws CertificateEncodingException, IOException {

        return PemUtils.encodeObjectToPEM(x509ServerCertificate);
    }

    public void generate (CA ca, String dn, Constants.KeyType mode, int validForDays)
            throws NoSuchAlgorithmException, OperatorCreationException,
            InvalidAlgorithmParameterException, NoSuchProviderException, IOException,
            CertificateException, InvalidKeySpecException {

        if (validForDays==0) { // 0 for default of 1 year
            validForDays = 365;
        }

        int keySize=-1;
        switch (mode) {
            case RSA:
            case RSAPSS:
                keySize=2048;
                break;
            case EC:
                keySize=256;
                break;
        }

        Csr csr = new Csr();
            csr.createCsr(mode, keySize, dn, null);
            keyPair = csr.getKeyPair();

            Signer signer = new Signer();

            signer.setValidTo(validForDays);
            String signedCertificate = signer.signServer(
                    PemUtils.encodeObjectToPEM(csr.getCsr()),
                    ca.getCaPrivateKeyPEM(),
                    ca.getCaCertificatePEM()
            );

            x509ServerCertificate = PemUtils.getCertificateFromPem (signedCertificate);

    }


    public void loadServerCertificate(String fileName, String password)
            throws CertificateException, NoSuchAlgorithmException, KeyStoreException,
            IOException, UnrecoverableKeyException {

        KeyStore keyStore = KeyStoreUtils.loadKeystore(
                fileName,
                password
        );

        keyPair = KeyStoreUtils.getKeypairFromKeystore(keyStore, password);
        x509ServerCertificate = KeyStoreUtils.getCertificateFromKeystore(keyStore, password);
    }


} // class
