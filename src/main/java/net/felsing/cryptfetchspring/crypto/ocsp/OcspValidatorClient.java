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

import java.math.BigInteger;
import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.concurrent.TimeUnit;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.ocsp.OCSPResponseStatus;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.SingleResp;
import io.netty.handler.ssl.OpenSsl;


/**
 * ATTENTION: This is an incomplete example! In order to provide a fully functional
 * end-to-end example we'd need an X.509 certificate and the matching PrivateKey.
 */
@SuppressWarnings("unused")
public class OcspValidatorClient {
    private static Logger logger = LogManager.getLogger(OcspValidatorClient.class);

    private OcspValidatorClient() {}

    public static OcspValidatorClient getInstance () {

        return new OcspValidatorClient();
    }


    public void validate(X509Certificate certificate, X509Certificate issuer) throws Exception {

        // Step 2: We need the URL of the CA's OCSP responder server. It's somewhere encoded
        // into the certificate! Notice that it's an HTTP URL.
        URI uri = OcspUtils.ocspUri(certificate);
        logger.info("OCSP Responder URI: " + uri);

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
        logger.info("Status: " + (status == CertificateStatus.GOOD ? "Good" : status));
        logger.info("This Update: " + first.getThisUpdate());
        logger.info("Next Update: " + first.getNextUpdate());

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

