package net.felsing.cryptfetchspring.crypto.config;

import org.slf4j.LoggerFactory;
import org.slf4j.Logger;
import java.security.Provider;
import java.security.Security;


public final class ProviderLoader {
    private static final Logger logger = LoggerFactory.getLogger(ProviderLoader.class);

    private static Provider provider;

    private ProviderLoader () {}

    static {
        loadBC();
    }


    private static void loadBC() {
        provider = new org.bouncycastle.jce.provider.BouncyCastleProvider();
        Security.addProvider(provider);
        if (logger.isInfoEnabled()) {
            logger.info(String.format("loaded provider %s", getProviderName()));
        }
    }


    public static Provider getProvider() {

        return provider;
    }


    public static String getProviderName() {

        return provider.getName();
    }

} // class
