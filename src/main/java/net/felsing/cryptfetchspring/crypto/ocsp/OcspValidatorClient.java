/*
 * Copyright 2017 The Netty Project
 *
 * The Netty Project licenses this file to you under the Apache License, version
 * 2.0 (the "License"); you may not use this file except in compliance with the
 * License. You may obtain a copy of the License at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */

package net.felsing.cryptfetchspring.crypto.ocsp;

import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.concurrent.TimeUnit;

import org.bouncycastle.cert.ocsp.*;
import org.bouncycastle.operator.OperatorCreationException;
import org.slf4j.LoggerFactory;
import org.slf4j.Logger;
import org.bouncycastle.asn1.ocsp.OCSPResponseStatus;
import io.netty.handler.ssl.OpenSsl;


/**
 * ATTENTION: This is an incomplete example! In order to provide a fully functional
 * end-to-end example we'd need an X.509 certificate and the matching PrivateKey.
 */
@SuppressWarnings("unused")
public class OcspValidatorClient {
    private static final Logger logger = LoggerFactory.getLogger(OcspValidatorClient.class);

    private OcspValidatorClient() {}

    public static OcspValidatorClient getInstance () {

        return new OcspValidatorClient();
    }


    public void validate(X509Certificate certificate, X509Certificate issuer)
            throws OperatorCreationException, IOException, CertificateEncodingException,
            OCSPException, URISyntaxException {

        // Step 2: We need the URL of the CA's OCSP responder server. It's somewhere encoded
        // into the certificate! Notice that it's an HTTP URL.
        URI uri = null;
        try {
            uri = OcspUtils.ocspUri(certificate);
        } catch (IOException e) {
            // do nothing
        }
        if (uri==null) {
            uri = OcspUtils.ocspUri(issuer);
        }

        if (logger.isInfoEnabled()) {
            logger.info(String.format("OCSP Responder URI: %s", uri));
        }

        if (uri == null) {
            throw new IllegalStateException("The CA/certificate doesn't have an OCSP responder");
        }

        // Step 3: Construct the OCSP request
        OCSPReq request = new OcspRequestBuilder()
                .certificate(certificate)
                .issuer(issuer)
                .build();

        // Step 4: Do the request to the CA's OCSP responder
        OCSPResp response = OcspUtils.request(uri, request, 5L, TimeUnit.SECONDS);
        if (response.getStatus() != OCSPResponseStatus.SUCCESSFUL) {
            throw new IllegalStateException("response-status=" + response.getStatus());
        }

        // Step 5: Is my certificate any good or has the CA revoked it?
        BasicOCSPResp basicResponse = (BasicOCSPResp) response.getResponseObject();
        SingleResp first = basicResponse.getResponses()[0];

        CertificateStatus status = first.getCertStatus();
        if (logger.isInfoEnabled()) {
            logger.info(String.format("Status: %s", (status == CertificateStatus.GOOD ? "Good" : status)));
            logger.info(String.format("This Update: %s", first.getThisUpdate()));
            logger.info(String.format("Next Update: %s", first.getNextUpdate()));
        }

        if (status != null) {
            throw new IllegalStateException("certificate-status=" + status);
        }

        BigInteger certSerial = certificate.getSerialNumber();
        BigInteger ocspSerial = first.getCertID().getSerialNumber();
        if (!certSerial.equals(ocspSerial)) {
            throw new IllegalStateException("Bad Serials=" + certSerial + " vs. " + ocspSerial);
        }

        // Step 6: Cache the OCSP response and use it as long as it's not
        // expired. The exact semantics are beyond the scope of this example.

        if (!OpenSsl.isAvailable()) {
            throw new IllegalStateException("OpenSSL is not available!");
        }

        if (!OpenSsl.isOcspSupported()) {
            throw new IllegalStateException("OCSP is not supported!");
        }

        throw new IllegalStateException("Because we don't have a PrivateKey we can't continue past this point.");

    }

}

