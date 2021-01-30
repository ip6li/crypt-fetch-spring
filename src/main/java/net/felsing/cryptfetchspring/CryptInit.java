package net.felsing.cryptfetchspring;


import net.felsing.cryptfetchspring.crypto.certs.CA;
import net.felsing.cryptfetchspring.crypto.certs.KeyStoreUtils;
import net.felsing.cryptfetchspring.crypto.certs.ServerCertificate;
import net.felsing.cryptfetchspring.crypto.config.Configuration;
import net.felsing.cryptfetchspring.crypto.config.Constants;
import net.felsing.cryptfetchspring.crypto.config.ProviderLoader;
import net.felsing.cryptfetchspring.crypto.util.URL;
import org.bouncycastle.operator.OperatorCreationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Properties;

public class CryptInit {
    private static final Logger logger = LoggerFactory.getLogger(CryptInit.class);

    private static CA ca;
    private static ServerCertificate serverCertificate;
    private static ServerCertificate serverSignerCertificate;
    private static Properties properties;
    private static String servletRootPath;

    private CryptInit () { }

    static CA getInstance (String rootPath)
            throws IOException, CertificateException, NoSuchAlgorithmException,
            UnrecoverableKeyException, KeyStoreException, InvalidAlgorithmParameterException,
            URISyntaxException, OperatorCreationException, NoSuchProviderException {
        assert ProviderLoader.getProviderName()!=null;
        if (ca == null) {
            servletRootPath = rootPath;
            ca = new CA();
            initPKIinfrastructure();
        }
        return ca;
    }

    private static void initPKIinfrastructure ()
            throws CertificateException, NoSuchAlgorithmException, OperatorCreationException,
            NoSuchProviderException, InvalidAlgorithmParameterException, IOException,
            KeyStoreException, UnrecoverableKeyException, URISyntaxException {
        final String CAFILE = "caFile";
        properties = new Configuration().getConfig();
        final File caFile = new File(String.format("%s/%s", servletRootPath, properties.getProperty(CAFILE)));
        final String keyStorePassword = properties.getProperty("keyStorePassword");
        Constants.KeyType mode = Constants.KeyType.valueOf(properties.getProperty("keyMode"));

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
            throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {

        Constants.KeyType mode = Constants.KeyType.valueOf(properties.getProperty("keyMode"));

        if (logger.isInfoEnabled()) {
            logger.info(String.format("generating new certificate: %s", serverKeyStoreFile));
        }

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
            throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException, URISyntaxException {

        loadServerCertificate();
        loadSignerCertificate();
    }

    private static void loadCertificate (ServerCertificate cert, String keyStoreFile, String keyStorePassword)
            throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {

        final File fKeyStore = new File(keyStoreFile);
        if (fKeyStore.exists()) {
            try {
                cert.loadServerCertificate(
                        keyStoreFile,
                        keyStorePassword
                );
                if (logger.isInfoEnabled()) {
                    logger.info(String.format("Using existing certificate %s", keyStoreFile));
                }
            } catch (Exception e) {
                logger.warn(e.getMessage());
            }
        } else {
            generateNewCertificate(cert, keyStoreFile, keyStorePassword);
        }
    }

    private static void loadServerCertificate ()
            throws URISyntaxException, CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        String serverKeyStoreFile = URL.urlToPath(servletRootPath, properties.getProperty(Constants.p_serverKeystoreFile));
        String serverKeyStorePassword = properties.getProperty(Constants.p_serverKeystorePassword);

        serverCertificate = new ServerCertificate();
        loadCertificate(serverCertificate, serverKeyStoreFile, serverKeyStorePassword);
    }


    private static void loadSignerCertificate ()
            throws URISyntaxException, CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        String signerKeyStoreFile = URL.urlToPath(servletRootPath, properties.getProperty(Constants.p_signerKeystoreFile));
        String signerKeyStorePassword = properties.getProperty(Constants.p_signerKeystorePassword);

        serverSignerCertificate = new ServerCertificate();
        loadCertificate(serverSignerCertificate, signerKeyStoreFile, signerKeyStorePassword);
    }

    public static ServerCertificate getServerCertificate() {

        return serverCertificate;
    }


    public static ServerCertificate getSignerCertificate () {

        return serverSignerCertificate;
    }


    public static CA getCa () {

        return ca;
    }

}
