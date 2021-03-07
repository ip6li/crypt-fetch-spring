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
import net.felsing.cryptfetchspring.crypto.util.Utils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.Properties;


public abstract class ConfigurationBase {
    private static final LogEngine logger = LogEngine.getLogger(ConfigurationBase.class);

    protected static final Properties config = new Properties();
    protected static File configFile;
    protected static String keystoreDefaultPassword;
    private static final boolean BCFIPS = Boolean.parseBoolean(readFromVMoptions("bcfips", "false"));


    ConfigurationBase() {
        if (config.isEmpty()) {
            try {
                loadConfig();
            } catch (IOException | NoSuchAlgorithmException e) {
                logger.error(String.format("Cannot load config file: %s%nLoading defaults", e.getMessage()));
            }

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


    private static void setConfigFile(File file) {
        configFile = file;
    }


    private static void setKeyStoreDefaultPassword (String p) {

        keystoreDefaultPassword = p;
    }


    private void loadConfig()
            throws IOException, NoSuchAlgorithmException {
        setConfigFile(Utils.findConfigFile(Constants.configFileName));
        logger.info(String.format("loadConfig: %s", configFile));
        if (configFile == null || !configFile.exists()) {
            setKeyStoreDefaultPassword(PemUtils.createRandomPassword());
            logger.warn("loadConfig: No config file found, loading defaults");
            preInit();
            init();
            saveConfig();
        } else {
            try (FileInputStream fileReader = new FileInputStream(configFile)) {
                config.loadFromXML(fileReader);
                setKeyStoreDefaultPassword(config.getProperty(Constants.d_serverKeystorePassword));
            } catch (Exception e) {
                logger.error(String.format("loadConfig: %s", e.getMessage()));
            }
        }
    }


    public static void saveConfig()
            throws IOException {
        try {
            logger.info(String.format("saveConfig: configFile found at %s", configFile.getAbsolutePath()));
        } catch (Exception e) {
            configFile = new File(Constants.configFileName);
            logger.info("saveConfig: creating new config file");
        }
        try (FileOutputStream propsFile = new FileOutputStream(Constants.configFileName)) {
            config.storeToXML(propsFile, "config");
        } catch (IOException e) {
            logger.error(String.format("saveConfig: %s", e.getMessage()));
            throw new IOException(e);
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

        logger.info(sb.toString());

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
