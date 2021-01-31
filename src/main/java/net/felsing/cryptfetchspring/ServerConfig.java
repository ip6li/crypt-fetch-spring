package net.felsing.cryptfetchspring;

import com.fasterxml.jackson.core.JsonProcessingException;
import net.felsing.cryptfetchspring.crypto.certs.CA;
import net.felsing.cryptfetchspring.crypto.certs.ServerCertificate;
import net.felsing.cryptfetchspring.crypto.config.ConfigModel;
import net.felsing.cryptfetchspring.crypto.config.Constants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;

import java.io.*;
import java.security.cert.CertificateEncodingException;
import java.util.ArrayList;
import java.util.HashMap;


/*************************************************************************************************************
 * Handles configuration items needed by service consumers
 *************************************************************************************************************/
public class ServerConfig {
    private static final Logger logger = LoggerFactory.getLogger(ServerConfig.class);

    private final ServerCertificate serverCertificate;
    private final CA ca;
    private static ServerConfig serverConfig = null;
    private static ConfigModel configuration;


    private ServerConfig(CA ca, ServerCertificate serverCertificate, InputStream defaultConfig)
            throws IOException {
        this.ca = ca;
        this.serverCertificate = serverCertificate;
        putConfigJson(defaultConfig);
    }


    public static ServerConfig getInstance(CA ca, ServerCertificate serverCertificate, InputStream defaultConfig)
            throws IOException {
        if (serverConfig == null) {
            serverConfig = new ServerConfig(ca, serverCertificate, defaultConfig);
        }
        return serverConfig;
    }


    public static ServerConfig getInstance(CA ca, ServerCertificate serverCertificate)
            throws IOException {
        if (serverConfig == null) {
            serverConfig = new ServerConfig(ca, serverCertificate, null);
        }
        return serverConfig;
    }


    public static ServerConfig getInstance() throws IOException {
        if (serverConfig == null) {
            throw new IOException("Needs to be initialized with 'getInstance (CA ca, ServerCertificate serverCertificate, ServerCertificate signerCertificate)' first");
        }
        return serverConfig;
    }


    private ArrayList<String> buildPossibleFileLocations(String filename) {
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

        fileLocations.forEach((v) -> logger.info(String.format("buildPossibleFileLocations: %s", v)));
        return fileLocations;
    }


    private File findConfigJson() {
        final String configJson = "config.json";
        final ArrayList<String> fileLocations = buildPossibleFileLocations(configJson);

        File[] result = new File[1];
        fileLocations.forEach(v -> {
            File test = new File(v);
            if (test.exists()) {
                result[0] = test;
            }
        });
        if (result[0] != null) {
            return result[0];
        }

        return null;
    }


    private void putConfigJson(InputStream defaultConfig) throws IOException {
        File fileLocation = findConfigJson();
        if (fileLocation == null) {
            logger.info("config.json not found, using default config from classpath");
            readConfiguration(defaultConfig);
        } else {
            try (FileInputStream jsonConfigFile = new FileInputStream(fileLocation.getAbsoluteFile())) {
                readConfiguration(jsonConfigFile);
            } catch (IOException e) {
                logger.error(e.getMessage());
            }
        }
    }


    private void readConfiguration(InputStream json) throws IOException {
        configuration = ConfigModel.deserialize(json);
        HashMap<String,String> remotekeystore = configuration.getRemotekeystore();
        remotekeystore.put(Constants.ca, ca.getCaCertificatePEM());
        try {
            remotekeystore.put(Constants.serverCert, serverCertificate.getServerCertificatePEM());
        } catch (CertificateEncodingException | IOException e) {
            logger.warn(e.getMessage());
        }
        configuration.setRemotekeystore(remotekeystore);
    }


    public static ServerConfig getServerConfig() {

        return serverConfig;
    }


    public String getConfig()
            throws JsonProcessingException {

        return new String(configuration.serialize());
    }

    public static ConfigModel createDefaultConfig() throws IOException {
        String json = "{\n" +
                "  \"config\": {\n" +
                "    \"same_enc_sign_cert\": true,\n" +
                "    \"keyAlg\": {\n" +
                "      \"hash\": \"SHA-256\",\n" +
                "      \"sign\": \"RSASSA-PKCS1-V1_5\",\n" +
                "      \"signDISABLED\": \"RSA-PSS\",\n" +
                "      \"modulusLength\": 2048\n" +
                "    },\n" +
                "    \"encAlg\": {\n" +
                "      \"name\": \"AES-CBC\",\n" +
                "      \"length\": 256\n" +
                "    },\n" +
                "    \"remotekeystore\": {},\n" +
                "    \"authURL\": \"http://127.0.0.1:8080/login\",\n" +
                "    \"messageURL\": \"http://127.0.0.1:8080/message\",\n" +
                "    \"renewURL\": \"http://127.0.0.1:8080/renew\"\n" +
                "  }\n" +
                "}";
        InputStream jsonStream = new ByteArrayInputStream(json.getBytes());
        return ConfigModel.deserialize(jsonStream);
    }

}
