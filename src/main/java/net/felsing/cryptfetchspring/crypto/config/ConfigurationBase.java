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

import org.slf4j.LoggerFactory;
import org.slf4j.Logger;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;


public abstract class ConfigurationBase {
    private static final Logger logger = LoggerFactory.getLogger(ConfigurationBase.class);

    protected static final Properties config = new Properties();
    private final String keystoreDefaultPassword;

    private static final boolean BCFIPS = Boolean.parseBoolean(readFromVMoptions("bcfips", "false"));


    ConfigurationBase() {
        String tmpPassword;
        try {
            Properties properties = loadDefaultsIni();
            tmpPassword = properties.getProperty("keystorePassword");
            logger.info(String.format("ConfigurationBase: %s", tmpPassword));
        } catch (IOException e) {
            logger.error(String.format("ConfigurationBase: %s", e.getMessage()));
            tmpPassword = null;
        }

        keystoreDefaultPassword = tmpPassword;
        if (config.isEmpty()) {
            preInit();
            init();
        }
    }

    /**
     * Get config as Properties object
     *
     * @return (Properties) :   Config
     */
    public Properties getConfig() {

        return config;
    }


    protected String getKeystoreDefaultPassword() {

        return keystoreDefaultPassword;
    }


    private Properties loadDefaultsIni() throws IOException {
        final String filename = "defaults.ini";
        Properties prop = new Properties();

        Resource configJsonFile = new ClassPathResource(filename);
        File f = configJsonFile.getFile();

        try (InputStream input = new FileInputStream(f)) {
            prop.load(input);
            return prop;
        }
    }


    static String readFromVMoptions(String key, String defaultValue) {
        StringBuilder sb = new StringBuilder();
        String value = System.getProperty(key);
        if (value == null) {
            value = defaultValue;
            sb.append("==> ").append(key).append(" is null -> set to ").append(value);
        } else {
            sb.append("==> ").append(key).append(" set to ").append(value);
        }
        if (logger.isInfoEnabled()) {
            logger.info(sb.toString());
        }
        return value;
    }


    private void preInit() {
        if (BCFIPS) {
            config.setProperty("bc", Configuration.BC_TYPE.BCFIPS.toString());
            config.setProperty("bcfips.rng", "C:DEFRND[SHA512];ENABLE{ALL};");
        } else {
            config.setProperty("bc", Configuration.BC_TYPE.BC.toString());
        }

        String isFips = config.getProperty("bc");
        if (isFips != null) {
            config.setProperty("js.fips",
                    Boolean.toString(
                            isFips.matches(
                                    Configuration.BC_TYPE.BCFIPS.toString()
                            )
                    )
            );
        }

        config.setProperty(Constants.p_serverKeystoreFile,
                readFromVMoptions(
                        Constants.p_serverKeystoreFile,
                        "server.p12"
                )
        );

        config.setProperty(Constants.d_serverKeystorePassword,
                readFromVMoptions(
                        Constants.d_serverKeystorePassword,
                        keystoreDefaultPassword
                )
        );

        config.setProperty(Constants.p_signerKeystoreFile,
                readFromVMoptions(
                        Constants.p_signerKeystoreFile,
                        "signer.p12"
                )
        );

        config.setProperty(Constants.d_signerKeystorePassword,
                readFromVMoptions(
                        Constants.d_signerKeystorePassword,
                        keystoreDefaultPassword
                )
        );

    }


    protected abstract void init();

} // class
