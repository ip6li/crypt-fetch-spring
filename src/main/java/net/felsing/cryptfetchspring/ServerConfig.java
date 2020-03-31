package net.felsing.cryptfetchspring;

import com.fasterxml.jackson.databind.ObjectMapper;
import net.felsing.cryptfetchspring.crypto.certs.CA;
import net.felsing.cryptfetchspring.crypto.certs.ServerCertificate;
import net.felsing.cryptfetchspring.crypto.config.Constants;
import net.felsing.cryptfetchspring.crypto.util.CheckedCast;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.util.HashMap;
import java.util.Map;


/*************************************************************************************************************
 * Handles configuration items needed by service consumers
 *************************************************************************************************************/
public class ServerConfig {
    private static Logger logger = LogManager.getLogger(ServerConfig.class);

    private ServerCertificate serverCertificate, signerCertificate;
    private CA ca;
    private static ServerConfig serverConfig = null;
    private static HashMap<String, Object> configuration;


    private ServerConfig (CA ca, ServerCertificate serverCertificate, ServerCertificate signerCertificate) {
        configuration = new HashMap<>();
        this.ca = ca;
        this.serverCertificate = serverCertificate;
        this.signerCertificate = signerCertificate;
        putConfigJson();
    }


    public static ServerConfig getInstance (CA ca, ServerCertificate serverCertificate, ServerCertificate signerCertificate) {
        if (serverConfig == null) {
            serverConfig = new ServerConfig(ca, serverCertificate, signerCertificate);
        }
        return serverConfig;
    }


    public static ServerConfig getInstance () throws IOException {
        if (serverConfig==null) {
            throw new IOException("Needs to be initialized with 'getInstance (CA ca, ServerCertificate serverCertificate, ServerCertificate signerCertificate)' first");
        }
        return serverConfig;
    }


    private void putCerts (Map<String, String> target) {
        target.put(Constants.ca, ca.getCaCertificatePEM());
        try {
            target.put(Constants.serverCert, serverCertificate.getServerCertificatePEM());
        } catch (CertificateEncodingException | IOException e) {
            logger.warn(e);
        }
    }


    private void putConfigJson () {
        try {
            Resource configJsonFile = new ClassPathResource("config.json");
            ObjectMapper objectMapper = new ObjectMapper();
            Map<?, ?> map = objectMapper.readValue(new FileInputStream(configJsonFile.getFile()), Map.class);
            logger.info("config.json found at " + configJsonFile.getFile());
            Map<?, ?> root = (Map<?, ?>) map.get("config");
            Map<? ,?> certs = (Map<?, ?>) root.get("remotekeystore");
            putCerts(CheckedCast.castToMapOf(String.class, String.class, certs));
            configuration.put("config", root);
        } catch (IOException e) {
            logger.error(e);
        }
    }


    public static ServerConfig getServerConfig () {

        return serverConfig;
    }


    public HashMap<String, Object> getConfig() {

        return configuration;
    }


    public static HashMap<String, Object> createDefaultConfig () {
        HashMap<String, Object> configRoot = new HashMap<>();
        HashMap<String, Object> config = new HashMap<>();
        HashMap<String, Object> keyAlg = new HashMap<>();
        HashMap<String, Object> encAlg = new HashMap<>();
        HashMap<String, String> remotekeystore = new HashMap<>();

        keyAlg.put("hash", "SHA-256");
        keyAlg.put("sign", "RSASSA-PKCS1-V1_5");
        keyAlg.put("modulusLength", 2048);

        encAlg.put("name", "AES-CBC");
        encAlg.put("length", 256);

        config.put("same_enc_sign_cert", true);
        config.put("keyAlg", keyAlg);
        config.put("encAlg", encAlg);
        config.put("remotekeystore", remotekeystore);
        config.put("authURL", "http://127.0.0.1:8080/login");
        config.put("messageURL", "http://127.0.0.1:8080/message");
        config.put("renewURL", "http://127.0.0.1:8080/renew");

        configRoot.put("config", config);

        return configRoot;
    }

}
