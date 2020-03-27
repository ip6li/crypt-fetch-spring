package net.felsing.cryptfetchspring;


import net.felsing.cryptfetchspring.crypto.certs.CA;
import net.felsing.cryptfetchspring.crypto.certs.Certificates;
import net.felsing.cryptfetchspring.crypto.certs.KeyStoreUtils;
import net.felsing.cryptfetchspring.crypto.certs.ServerCertificate;
import net.felsing.cryptfetchspring.crypto.config.Configuration;
import net.felsing.cryptfetchspring.crypto.config.Constants;
import net.felsing.cryptfetchspring.crypto.config.ProviderLoader;
import net.felsing.cryptfetchspring.crypto.util.URL;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;

import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Properties;

public class CryptInit {
    private static Logger logger = LogManager.getLogger(CryptInit.class.getName());

    private static CA ca;
    private static ServerCertificate serverCertificate, serverSignerCertificate;
    private static Properties properties;
    private static String servletRootPath;

    static CA getInstance (String rootPath) throws Exception {
        assert ProviderLoader.getProviderName()!=null;
        if (ca == null) {
            servletRootPath = rootPath;
            ca = new CA();
            initPKIinfrastructure();
        }
        return ca;
    }

    private static void initPKIinfrastructure () throws Exception {
        properties = new Configuration().getConfig();
        final File caFile = new File(properties.getProperty("caFile"));
        final String keyStorePassword = properties.getProperty("keyStorePassword");
        Certificates.KeyType mode = Certificates.KeyType.valueOf(properties.getProperty("keyMode"));

        if (!caFile.exists()) {
            String caDN = properties.getProperty("ca.dnPrefix") +
                    " " + mode.toString() + "," +
                    properties.getProperty("ca.dnSuffix");

            ca.createCertificationAuthority(
                    mode,
                    caDN,
                    Integer.valueOf(properties.getProperty("ca.days"))
            );

            ca.saveCertificationAuthorityKeystore(properties.getProperty("caFile"), keyStorePassword);
        } else {
            String p12rsa = properties.getProperty("caFile");
            ca.loadCertificationAuthorityKeystore(p12rsa, keyStorePassword);
        }

        loadCertificates();
    }

    private static void generateNewCertificate(ServerCertificate cert, String serverKeyStoreFile, String serverKeyStorePassword)
            throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {

        Certificates.KeyType mode = Certificates.KeyType.valueOf(properties.getProperty("keyMode"));

        logger.info("generating new certificate: " + serverKeyStoreFile);

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
                logger.info("Using existing certificate " + keyStoreFile);
            } catch (Exception e) {
                e.printStackTrace();
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
