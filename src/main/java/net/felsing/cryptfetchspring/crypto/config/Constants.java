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

package net.felsing.cryptfetchspring.crypto.config;


public final class Constants {

    public enum KeyType { RSA, RSAPSS, EC }

    // attribute ids
    public static final String SHA_256_WITH_ECDSA = "SHA256withECDSA";
    public static final String SHA_256_WITH_RSA = "SHA256withRSA";
    public static final String SHA_384_WITH_RSA_AND_MGF1 = "SHA384withRSAandMGF1";

    // PEM tags
    public static final String CMS_BEGIN = "-----BEGIN CMS-----";
    public static final String CMS_END = "-----END CMS-----";
    public static final String PRIVATE_KEY_BEGIN = "-----BEGIN PRIVATE KEY-----";
    public static final String PRIVATE_KEY_END = "-----END PRIVATE KEY-----";
    public static final String PUBLIC_KEY_BEGIN = "-----BEGIN PUBLIC KEY-----";
    public static final String PUBLIC_KEY_END = "-----END PUBLIC KEY-----";
    public static final String CSR_BEGIN = "-----BEGIN CERTIFICATE REQUEST-----";
    public static final String CSR_END = "-----END CERTIFICATE REQUEST-----";
    public static final String CRT_BEGIN ="-----BEGIN CERTIFICATE-----";
    public static final String CRT_END ="-----END CERTIFICATE-----";

    public static final String keyAlgoOidEC = "1.2.840.10045.2.1";
    public static final String oidSan = "2.5.29.19";

    // properties
    public static final String p_serverKeystoreFile = "servercert.keystore.file";
    public static final String p_signerKeystoreFile = "signercert.keystore.file";

    // -D parameters
    public static final String d_serverKeystorePassword = "serverKeystorePassword";
    public static final String d_signerKeystorePassword = "d_signerKeystorePassword";

    // how long CA should live
    public static final int caDays = 30 * 365;

    // for debugging
    public final static boolean enableOriginatorInfo = true;

    // Config hash key names
    public final static String ca = "ca";
    public final static String serverCert = "server";

    public final static int[] allowedSanTypes = {0, 1, 2, 6, 7};

    // Properties names
    public final static String prop_js_sign = "js.sign";
    public final static String prop_keyMode = "keyMode";
    public final static String prop_server_DN = "server.DN";
    public final static String prop_signer_DN = "signer.DN";
    public final static String prop_caFile = "caFile";
    public final static String prop_js_url = "js.url";
    public final static String prop_js_hash = "js.hash";
    public final static String prop_keyStorePassword = "keyStorePassword";
    public final static String prop_ca_dnSuffix = "ca.dnSuffix";
    public final static String prop_ca_dnPrefix = "ca.dnPrefix";
    public final static String prop_ca_days = "ca.days";
    public final static String prop_server_days = "server.days";
    public final static String prop_signer_days = "signer.days";
    public final static String prop_certificate_days = "certificate.days";
}
