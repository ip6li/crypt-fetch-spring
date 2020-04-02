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


import java.io.*;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.cert.X509Certificate;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.HttpsURLConnection;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;


@SuppressWarnings("unused")
public final class OcspUtils {
    /**
     * The OID for OCSP responder URLs.
     * <p>
     * http://www.alvestrand.no/objectid/1.3.6.1.5.5.7.48.1.html
     */
    //private static final ASN1ObjectIdentifier OCSP_RESPONDER_OID
    //        = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.48.1").intern();
    private static final ASN1ObjectIdentifier OCSP_RESPONDER_OID
            = AccessDescription.id_ad_ocsp.intern();

    private static final String OCSP_REQUEST_TYPE = "application/ocsp-request";

    private static final String OCSP_RESPONSE_TYPE = "application/ocsp-response";

    private OcspUtils() {
    }

    /**
     * Returns the OCSP responder {@link URI} or {@code null} if it doesn't have one.
     */
    public static URI ocspUri(X509Certificate certificate) throws IOException, URISyntaxException {
        ASN1Primitive authorityInfoAccess = getExtensionValue(
                certificate,
                Extension.authorityInfoAccess.getId()
        );
        if (authorityInfoAccess == null) {
            return null;
        }

        AuthorityInformationAccess authorityInformationAccess = AuthorityInformationAccess.getInstance(authorityInfoAccess);

        AccessDescription[] accessDescriptions = authorityInformationAccess.getAccessDescriptions();
        for (AccessDescription accessDescription : accessDescriptions) {
            boolean correctAccessMethod = accessDescription.getAccessMethod().equals(X509ObjectIdentifiers.ocspAccessMethod);
            if (!correctAccessMethod) {
                continue;
            }

            GeneralName name = accessDescription.getAccessLocation();
            if (name.getTagNo() != GeneralName.uniformResourceIdentifier) {
                continue;
            }

            DERIA5String derStr = DERIA5String.getInstance((ASN1TaggedObject) name.toASN1Primitive(), false);
            return new URI(derStr.getString());
        }

        return null;
    }

    private static <T> T findObject(DLSequence sequence) {
        for (ASN1Encodable element : sequence) {
            if (!(element instanceof DLSequence)) {
                continue;
            }

            DLSequence subSequence = (DLSequence) element;
            if (subSequence.size() != 2) {
                continue;
            }

            ASN1Encodable key = subSequence.getObjectAt(0);
            ASN1Encodable value = subSequence.getObjectAt(1);

            if (key.equals(OcspUtils.OCSP_RESPONDER_OID) && value instanceof DERTaggedObject) {
                return ((Class<T>) DERTaggedObject.class).cast(value);
            }
        }

        return null;
    }

    /**
     * TODO: This is a very crude and non-scalable HTTP client to fetch the OCSP response from the
     * CA's OCSP responder server. It's meant to demonstrate the basic building blocks on how to
     * interact with the responder server and you should consider using Netty's HTTP client instead.
     */
    public static OCSPResp request(URI uri, OCSPReq request, long timeout, TimeUnit unit) throws IOException {
        byte[] encoded = request.getEncoded();

        URL url = uri.toURL();
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        try {
            connection.setConnectTimeout((int) unit.toMillis(timeout));
            connection.setReadTimeout((int) unit.toMillis(timeout));
            connection.setDoOutput(true);
            connection.setDoInput(true);
            connection.setRequestMethod("POST");
            connection.setRequestProperty("host", uri.getHost());
            connection.setRequestProperty("content-type", OCSP_REQUEST_TYPE);
            connection.setRequestProperty("accept", OCSP_RESPONSE_TYPE);
            connection.setRequestProperty("content-length", String.valueOf(encoded.length));

            try (OutputStream out = connection.getOutputStream()) {
                out.write(encoded);
                out.flush();

                try (InputStream in = connection.getInputStream()) {
                    int code = connection.getResponseCode();
                    if (code != HttpsURLConnection.HTTP_OK) {
                        throw new IOException("Unexpected status-code=" + code);
                    }

                    String contentType = connection.getContentType();
                    if (!contentType.equalsIgnoreCase(OCSP_RESPONSE_TYPE)) {
                        throw new IOException("Unexpected content-type=" + contentType);
                    }

                    int contentLength = connection.getContentLength();
                    if (contentLength == -1) {
                        // Probably a terrible idea!
                        contentLength = Integer.MAX_VALUE;
                    }

                    ByteArrayOutputStream baos = new ByteArrayOutputStream();
                    try (baos) {
                        byte[] buffer = new byte[8192];
                        int length;

                        while ((length = in.read(buffer)) != -1) {
                            baos.write(buffer, 0, length);

                            if (baos.size() >= contentLength) {
                                break;
                            }
                        }
                    }
                    return new OCSPResp(baos.toByteArray());
                }
            }
        } finally {
            connection.disconnect();
        }
    }

    private static ASN1Primitive getExtensionValue(X509Certificate certificate, String oid) throws IOException {
        byte[] bytes = certificate.getExtensionValue(oid);
        if (bytes == null) {
            return null;
        }
        ASN1InputStream aIn = new ASN1InputStream(new ByteArrayInputStream(bytes));
        ASN1OctetString octs = (ASN1OctetString) aIn.readObject();
        aIn = new ASN1InputStream(new ByteArrayInputStream(octs.getOctets()));
        return aIn.readObject();
    }

}
