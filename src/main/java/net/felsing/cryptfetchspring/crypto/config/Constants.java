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

    // attribute ids
    public static final String att_validated = "x509validated";
    public static final String att_error = "x509error";

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

    // OIDs
    public static final String keyAlgoOidRSA = "1.2.840.113549.1.1.1";
    public static final String keyAlgoOidEC = "1.2.840.10045.2.1";
    public static final String oidSan = "2.5.29.19";

    // ids for Json fields
    public static final String id_data = "data";
    public static final String id_error = "error";
    public static final String id_certificates = "certificates";
    public static final String id_certificateChain = "certificateChain";
    public static final String id_pkcs10 = "pkcs10";
    public static final String id_serverCert = "serverCert";
    public static final String id_validationOk = "validationOk";
    public static final String id_exception ="exception";

    // cmd ids
    public static final String cmd ="cmd";
    public static final String do_cms ="doCms";
    public static final String do_sign = "doSign";
    public static final String do_get_config = "getConfig";

    // properties
    public static final String p_serverKeystoreFile = "servercert.keystore.file";
    public static final String p_serverKeystorePassword = "changeit";
    public static final String p_signerKeystoreFile = "signercert.keystore.file";
    public static final String p_signerKeystorePassword = "changeit";

    // errors
    public static final String err_msg = "msg";
    public static final String err_unknown = "unknown request";
    public static final String err_notReady = "not ready";
    public static final String err_ok = "ok";
    public static final String err_failed = "failed";

    // -D parameters
    static final String d_serverKeystorePassword = "serverKeystorePassword";
    static final String d_signerKeystorePassword = "d_signerKeystorePassword";

    // how long CA should live
    public static final int caDays = 30 * 365;

    // for debugging
    public static boolean enableOriginatorInfo = true;

}
