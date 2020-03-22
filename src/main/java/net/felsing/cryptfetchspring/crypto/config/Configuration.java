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


import net.felsing.cryptfetchspring.crypto.certs.Certificates;


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

    public enum BC_TYPE {bc, bcfips}

    private final static boolean useEC = Boolean.parseBoolean(readFromVMoptions("ec", "false"));


    @Override
    protected void init() {

        config.setProperty("js.url", readFromVMoptions("url", "index"));
        config.setProperty("js.hash", "SHA-256");

        config.setProperty("keyStorePassword", "changeit");
        config.setProperty("ca.dnSuffix", "O=Honest Achmed,OU=Used Cars,C=DE");
        config.setProperty("ca.dnPrefix", "CN=Honest Achmets trustworthy CA");
        config.setProperty("ca.days", Long.toString(30 * 365));
        config.setProperty("server.days", Integer.toString(10 * 365));
        config.setProperty("signer.days", Integer.toString(10 * 365));

        // use either RSA or ECDSA
        if (useEC) {
            config.setProperty("js.sign", "ECDSA");
            config.setProperty("keyMode", Certificates.KeyType.EC.toString());
            config.setProperty("server.DN", "CN=The server certificate ECDSA");
            config.setProperty("signer.DN", "CN=The signer certificate ECDSA");
            config.setProperty("caFile", "/WEB-INF/classes/CA-ECDSA.p12");
        } else {
            config.setProperty("js.sign", "RSASSA-PKCS1-V1_5");
            config.setProperty("keyMode", Certificates.KeyType.RSA.toString());
            config.setProperty("server.DN", "CN=The server certificate RSA");
            config.setProperty("signer.DN", "CN=The signer certificate RSA");
            config.setProperty("caFile", "/WEB-INF/classes/CA-RSA.p12");
        }
    }

} // class
