package net.felsing.cryptfetchspring.crypto.certs;


import net.felsing.cryptfetchspring.crypto.config.Constants;
import net.felsing.cryptfetchspring.crypto.config.ProviderLoader;
import net.felsing.cryptfetchspring.crypto.util.LogEngine;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.DefaultAlgorithmNameFinder;

import java.io.IOException;
import java.security.*;
import java.security.spec.ECGenParameterSpec;


public final class KeyUtils {
    private static final LogEngine logger = LogEngine.getLogger(KeyUtils.class);

    public static final String RSA = "RSA";
    public static final String RSAPSS = "RSASSA-PSS";
    public static final String EC = "EC";
    public static final String ECCURVE = "prime256v1";
    public static final String RSA_REGEX = "SHA.*RSA";

    private KeyUtils () {}

    public static KeyPair generateKeypairRSA(int size, String algorithm)
            throws NoSuchProviderException, NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm, ProviderLoader.getProviderName());
        keyPairGenerator.initialize(size, new SecureRandom());
        return keyPairGenerator.generateKeyPair();
    }

    public static KeyPair generateKeypairRSA(int size)
            throws NoSuchProviderException, NoSuchAlgorithmException {

        return generateKeypairRSA(size, RSA);
    }

    public static KeyPair generateKeypairRSAPSS(int size)
            throws NoSuchProviderException, NoSuchAlgorithmException {

        return generateKeypairRSA(size, RSAPSS);
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

        return generateKeypairEC(EC, ECCURVE);
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
            case RSAPSS:
                return generateKeypairRSAPSS(size);
            case EC:
                return generateKeypairEC();
        }
        throw new NoSuchProviderException("Algorithm not implemented: " + keyType.toString());
    }


    public static String deriveKeyFactoryFromAlg (String alg, boolean isId) throws IOException {
        logger.info(String.format("deriveKeyFactoryFromAlg: %s", alg));
        String algorithmName;
        if (isId) {
            algorithmName = new DefaultAlgorithmNameFinder().getAlgorithmName(new AlgorithmIdentifier(new ASN1ObjectIdentifier(alg)));
        } else {
            algorithmName = alg;
        }
        if (algorithmName.matches("SHA.*ECDSA")) {
            logger.info("deriveKeyFactoryFromAlg: csrKeyAlgorithm using EC");
            return  EC;
        } else if (algorithmName.matches(RSA_REGEX)) {
            return RSA;
        } else if (algorithmName.matches("RSAPSS")) {
            return RSAPSS;
        } else {
            throw new IOException(String.format("deriveKeyFactoryFromAlg: Cannot determine a keyfactory name for %s", algorithmName));
        }
    }

}
