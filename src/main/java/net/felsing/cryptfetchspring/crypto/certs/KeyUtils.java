package net.felsing.cryptfetchspring.crypto.certs;


import net.felsing.cryptfetchspring.crypto.config.Constants;
import net.felsing.cryptfetchspring.crypto.config.ProviderLoader;

import java.security.*;
import java.security.spec.ECGenParameterSpec;


public final class KeyUtils {

    public static KeyPair generateKeypairRSA(int size, String algorithm)
            throws NoSuchProviderException, NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm, ProviderLoader.getProviderName());
        keyPairGenerator.initialize(size, new SecureRandom());
        return keyPairGenerator.generateKeyPair();
    }

    public static KeyPair generateKeypairRSA(int size)
            throws NoSuchProviderException, NoSuchAlgorithmException {

        return generateKeypairRSA(size, "RSA");
    }

    public static KeyPair generateKeypairEC(String algorithm, String curve)
            throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator kpgen = KeyPairGenerator.getInstance(algorithm, ProviderLoader.getProviderName());
        ECGenParameterSpec ec = new ECGenParameterSpec(curve);
        kpgen.initialize(ec, new SecureRandom());
        return kpgen.generateKeyPair();
    }

    public static KeyPair generateKeypairEC()
            throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {

        return generateKeypairEC("ECDSA", "prime256v1");
    }


    /**
     * @param keyType "RSA" or "EC"
     * @throws NoSuchProviderException  from KeyPairGenerator
     * @throws NoSuchAlgorithmException from KeyPairGenerator
     */
    public static KeyPair generateKeypair(Constants.KeyType keyType, int size)
            throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {

        switch (keyType) {
            case RSA:
                return generateKeypairRSA(size);
            case EC:
                return generateKeypairEC();
        }
        throw new NoSuchProviderException("Algorithm not implemented: " + keyType.toString());
    }

}
