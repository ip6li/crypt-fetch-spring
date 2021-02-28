package net.felsing.cryptfetchspring;


import net.felsing.cryptfetchspring.crypto.certs.CA;
import net.felsing.cryptfetchspring.crypto.certs.KeyStoreUtils;
import net.felsing.cryptfetchspring.crypto.certs.ServerCertificate;
import net.felsing.cryptfetchspring.crypto.config.Configuration;
import net.felsing.cryptfetchspring.crypto.config.Constants;
import net.felsing.cryptfetchspring.crypto.config.ProviderLoader;
import net.felsing.cryptfetchspring.crypto.util.LogEngine;
import net.felsing.cryptfetchspring.crypto.util.URL;
import org.bouncycastle.operator.OperatorCreationException;

import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.Properties;

public class CryptInit {
    private static final LogEngine logger = LogEngine.getLogger(CryptInit.class);

    private static CA ca;
    private static ServerCertificate serverCertificate;
    private static ServerCertificate serverSignerCertificate;
    private static Properties properties;
    private static String servletRootPath;

    private CryptInit() {
    }

    static CA getInstance(String rootPath)
            throws IOException, CertificateException, NoSuchAlgorithmException,
            UnrecoverableKeyException, KeyStoreException, InvalidAlgorithmParameterException,
            URISyntaxException, OperatorCreationException, NoSuchProviderException, InvalidKeySpecException {
        assert ProviderLoader.getProviderName() != null;
        if (ca == null) {
            servletRootPath = rootPath;
            ca = new CA();
            initPKIinfrastructure();
        }
        return ca;
    }

    private static void initPKIinfrastructure()
            throws CertificateException, NoSuchAlgorithmException, OperatorCreationException,
            NoSuchProviderException, InvalidAlgorithmParameterException, IOException,
            KeyStoreException, UnrecoverableKeyException, URISyntaxException, InvalidKeySpecException {
        final String CAFILE = "caFile";
        properties = new Configuration().getConfig();
        final File caFile = new File(String.format("%s/%s", servletRootPath, properties.getProperty(CAFILE)));
        final String keyStorePassword = properties.getProperty("keyStorePassword");
        Constants.KeyType mode = Constants.KeyType.valueOf(properties.getProperty("keyMode"));
        logger.info(String.format("initPKIinfrastructure: %s", mode));

        if (!caFile.exists()) {
            String caDN = properties.getProperty("ca.dnPrefix") +
                    " " + mode.toString() + "," +
                    properties.getProperty("ca.dnSuffix");

            ca.createCertificationAuthority(
                    mode,
                    caDN,
                    Integer.valueOf(properties.getProperty("ca.days"))
            );

            ca.saveCertificationAuthorityKeystore(caFile.getAbsolutePath(), keyStorePassword);
        } else {
            ca.loadCertificationAuthorityKeystore(caFile.getAbsolutePath(), keyStorePassword);
        }

        loadCertificates();
    }

    private static void generateNewCertificate(ServerCertificate cert, String serverKeyStoreFile, String serverKeyStorePassword)
            throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException,
            InvalidAlgorithmParameterException, OperatorCreationException, NoSuchProviderException,
            InvalidKeySpecException {

        Constants.KeyType mode = Constants.KeyType.valueOf(properties.getProperty("keyMode"));

        logger.info(String.format("generating new certificate: %s", serverKeyStoreFile));

        File f = new File(serverKeyStoreFile);
        if (f.exists()) {
            throw new IOException("cannot generate new server certificate: File " + serverKeyStoreFile + " already exists");
        }

        cert.generate(
                ca,
                properties.getProperty("server.DN"),
                mode,
                Integer.parseInt(properties.getProperty("server.days"))
        );
        KeyStoreUtils.saveToKeystore(
                cert.getServerCertificate().getSubjectDN().getName(),
                cert.getServerKeyPair(),
                cert.getServerCertificate(),
                serverKeyStoreFile,
                serverKeyStorePassword
        );
    }

    private static void loadCertificates()
            throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException,
            URISyntaxException, InvalidAlgorithmParameterException, OperatorCreationException,
            NoSuchProviderException, InvalidKeySpecException {

        loadServerCertificate();
        loadSignerCertificate();
    }

    private static void loadCertificate(ServerCertificate cert, String keyStoreFile, String keyStorePassword)
            throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException,
            InvalidAlgorithmParameterException, OperatorCreationException, NoSuchProviderException,
            InvalidKeySpecException {

        final File fKeyStore = new File(keyStoreFile);
        if (fKeyStore.exists()) {
            try {
                cert.loadServerCertificate(
                        keyStoreFile,
                        keyStorePassword
                );
                logger.info(String.format("Using existing certificate %s", keyStoreFile));
            } catch (Exception e) {
                logger.warn(e.getMessage());
            }
        } else {
            generateNewCertificate(cert, keyStoreFile, keyStorePassword);
        }
    }

    private static void loadServerCertificate()
            throws URISyntaxException, CertificateException, NoSuchAlgorithmException, KeyStoreException,
            IOException, InvalidAlgorithmParameterException, OperatorCreationException, NoSuchProviderException,
            InvalidKeySpecException {
        String serverKeyStoreFile = URL.urlToPath(servletRootPath, properties.getProperty(Constants.p_serverKeystoreFile));
        String serverKeyStorePassword = properties.getProperty(Constants.d_serverKeystorePassword);

        serverCertificate = new ServerCertificate();
        loadCertificate(serverCertificate, serverKeyStoreFile, serverKeyStorePassword);
    }


    private static void loadSignerCertificate()
            throws URISyntaxException, CertificateException, NoSuchAlgorithmException, KeyStoreException,
            IOException, InvalidAlgorithmParameterException, OperatorCreationException, NoSuchProviderException,
            InvalidKeySpecException {
        String signerKeyStoreFile = URL.urlToPath(servletRootPath, properties.getProperty(Constants.p_signerKeystoreFile));
        String signerKeyStorePassword = properties.getProperty(Constants.d_signerKeystorePassword);

        serverSignerCertificate = new ServerCertificate();
        loadCertificate(serverSignerCertificate, signerKeyStoreFile, signerKeyStorePassword);
    }

    public static ServerCertificate getServerCertificate() {

        return serverCertificate;
    }


    public static ServerCertificate getSignerCertificate() {

        return serverSignerCertificate;
    }


    public static CA getCa() {

        return ca;
    }

}
