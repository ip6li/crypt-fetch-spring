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

import net.felsing.cryptfetchspring.crypto.util.LogEngine;
import net.felsing.cryptfetchspring.crypto.util.PemUtils;

import java.security.NoSuchAlgorithmException;

/**
 * This class provides configuration properties, which can be used to get
 * as Properties or JsonObject. Properties with prefix "js." are provided
 * to client.
 * <p>
 * Usage:
 * Configuration = new Configuration ();
 * getConfig() or getConfigJson()
 */

public final class Configuration extends ConfigurationBase {
    public enum BC_TYPE {BC, BCFIPS}

    private static final Constants.KeyType keyType = Constants.KeyType.EC;


    @Override
    protected void init() {
        final int oneYear = 365;

        config.setProperty(Constants.prop_js_url, readFromVMoptions("url", "index"));
        config.setProperty(Constants.prop_js_hash, "SHA-256");

        // who is Honest Achmet? See https://bugzilla.mozilla.org/show_bug.cgi?id=647959
        config.setProperty(Constants.prop_ca_dnSuffix, "O=Honest Achmed,OU=Used Cars,C=DE");
        config.setProperty(Constants.prop_ca_dnPrefix, "CN=Honest Achmets trustworthy CA");
        config.setProperty(Constants.prop_ca_days, Long.toString(30L * oneYear));
        config.setProperty(Constants.prop_server_days, Integer.toString(10 * oneYear));
        config.setProperty(Constants.prop_signer_days, Integer.toString(10 * oneYear));
        config.setProperty(Constants.prop_certificate_days, Integer.toString(1));

        switch (keyType) {
            case EC:
                config.setProperty(Constants.prop_js_sign, "ECDSA");
                config.setProperty(Constants.prop_keyMode, Constants.KeyType.EC.toString());
                config.setProperty(Constants.prop_server_DN, "CN=The server certificate ECDSA");
                config.setProperty(Constants.prop_signer_DN, "CN=The signer certificate ECDSA");
                config.setProperty(Constants.prop_caFile, "CA-ECDSA.p12");
                break;
            case RSA:
                config.setProperty(Constants.prop_js_sign, "RSASSA-PKCS1-V1_5");
                config.setProperty(Constants.prop_keyMode, Constants.KeyType.RSA.toString());
                config.setProperty(Constants.prop_server_DN, "CN=The server certificate RSA");
                config.setProperty(Constants.prop_signer_DN, "CN=The signer certificate RSA");
                config.setProperty(Constants.prop_caFile, "CA-RSA.p12");
                break;
            case RSAPSS:
                config.setProperty(Constants.prop_js_sign, "RSASSA-PSS");
                config.setProperty(Constants.prop_keyMode, Constants.KeyType.RSAPSS.toString());
                config.setProperty(Constants.prop_server_DN, "CN=The server certificate RSA");
                config.setProperty(Constants.prop_signer_DN, "CN=The signer certificate RSA");
                config.setProperty(Constants.prop_caFile, "CA-RSA.p12");
                break;
        }
    }

} // class
