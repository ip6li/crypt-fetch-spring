package net.felsing.cryptfetchspring.crypto.config;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import java.security.Provider;
import java.security.Security;


public final class ProviderLoader {
    private static final Logger logger = LogManager.getLogger(ProviderLoader.class);

    private static Provider provider;


    static {
        loadBC();
    }


    private static void loadBC() {
        provider = new org.bouncycastle.jce.provider.BouncyCastleProvider();
        Security.addProvider(provider);
        logger.info("loaded provider " + getProviderName());
    }


    public static Provider getProvider() {

        return provider;
    }


    public static String getProviderName() {

        return provider.getName();
    }

} // class
