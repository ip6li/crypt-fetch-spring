package net.felsing.cryptfetchspring.crypto.util;

import java.security.SecureRandom;

public class Random extends SecureRandom {

    private static SecureRandom secureRandom = null;

    public static SecureRandom getSecureRandom () {
        if (secureRandom==null) {
            secureRandom = new SecureRandom();
        }
        return secureRandom;
    }
}
