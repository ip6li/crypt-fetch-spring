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

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;


/*************************************************************************************************************
 * Handles configuration items needed by service consumers
 *************************************************************************************************************/
public class ServerConfig {
    private static final Logger logger = LogManager.getLogger(ServerConfig.class);

    private final ServerCertificate serverCertificate;
    private final ServerCertificate signerCertificate;
    private final CA ca;
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


    private ArrayList<String> buildPossibleFileLocations (String filename) {
        final ArrayList<String> fileLocations = new ArrayList<>();
        try {
            Resource configJsonFile = new ClassPathResource(filename);
            File f = configJsonFile.getFile();
            if (f.exists()) {
                fileLocations.add(f.getAbsolutePath());
            }
        } catch (IOException e) {
            // do nothing
        }
        fileLocations.add("./" + filename);
        fileLocations.add(System.getProperty("user.home") + "/.crypt-fetch/" + filename);
        fileLocations.add("/etc/crypt-fetch/" + filename);

        return fileLocations;
    }


    private File findConfigJson () {
        final String configJson = "config.json";
        final ArrayList<String> fileLocations = buildPossibleFileLocations(configJson);

        File[] result=new File[1];
        fileLocations.forEach((v)->{
            File test = new File(v);
            if (test.exists()) {
                result[0] = test;
            }
        });
        if (result[0]!=null) {
            return result[0];
        }

        logger.error("config.json nowhere found");
        return null;
    }



    private void putConfigJson () {
        try {
            File fileLocation = findConfigJson();
            if (fileLocation==null) {
                logger.info("config.json not found");
            }
            assert fileLocation != null;
            ObjectMapper objectMapper = new ObjectMapper();
            Map<?, ?> map = objectMapper.readValue(new FileInputStream(fileLocation.getAbsoluteFile()), Map.class);
            logger.info("config.json found at " + fileLocation.getAbsolutePath());
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
