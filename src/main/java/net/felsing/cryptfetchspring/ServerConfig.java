package net.felsing.cryptfetchspring;

import com.fasterxml.jackson.databind.ObjectMapper;
import net.felsing.cryptfetchspring.crypto.certs.CA;
import net.felsing.cryptfetchspring.crypto.certs.ServerCertificate;
import net.felsing.cryptfetchspring.crypto.config.Constants;
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
        HashMap<String, String> certs = new HashMap<>();
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
            putCerts((Map<String, String>) certs);
            configuration.put("config", root);
        } catch (IOException e) {
            logger.error(e);
        }
    }


    public static ServerConfig getServerConfig () {

        return serverConfig;
    }


    public HashMap<String, Object> getConfig() {
        //ToDo: Deliver server/ca certificate and urls for further operations
        return configuration;
    }

}
