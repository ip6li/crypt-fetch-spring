package net.felsing.cryptfetchspring.crypto.config;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Provider;
import java.security.Security;


public final class ProviderLoader {
    private static Logger logger = LogManager.getLogger(ProviderLoader.class);

    private static Provider provider;


    static {
        load();
    }


    private static void load() {
        loadBC();
    }


    private static void loadBC() {

        provider = new org.bouncycastle.jce.provider.BouncyCastleProvider();
        Security.addProvider(provider);
        logger.info("loaded provider " + getProviderName());
    }


    // for future use with Bouncy Castle FIPS
    /*
    private static void loadBC () {
        Configuration configuration = new Configuration();
        String options = configuration.getConfig().getProperty("bcfips.rng");
        if (options == null) {
            options = "C:DEFRND[SHA512];ENABLE{ALL};";
        }
        provider = new org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider(options);
        logger.info("loaded provider " + getProviderName());
    }
    */


    public static Provider getProvider() {

        return provider;
    }


    public static String getProviderName() {

        return provider.getName();
    }

} // class
