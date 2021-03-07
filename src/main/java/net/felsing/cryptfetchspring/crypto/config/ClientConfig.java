package net.felsing.cryptfetchspring.crypto.config;

import com.fasterxml.jackson.core.JsonProcessingException;
import net.felsing.cryptfetchspring.crypto.certs.CA;
import net.felsing.cryptfetchspring.crypto.certs.ServerCertificate;
import net.felsing.cryptfetchspring.crypto.util.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.security.cert.CertificateEncodingException;
import java.util.HashMap;
import java.util.Map;


/*************************************************************************************************************
 * Handles configuration items needed by service consumers
 *************************************************************************************************************/
public class ClientConfig {
    private static final Logger logger = LoggerFactory.getLogger(ClientConfig.class);

    private final ServerCertificate serverCertificate;
    private final CA ca;
    private static ClientConfig clientConfig = null;
    private static ClientConfigModel clientConfigModel;
    private static final Configuration configuration = new Configuration();



    private ClientConfig(CA ca, ServerCertificate serverCertificate, InputStream defaultConfig)
            throws IOException {
        this.ca = ca;
        this.serverCertificate = serverCertificate;
        putConfigJson(defaultConfig);
    }


    public static ClientConfig getInstance(CA ca, ServerCertificate serverCertificate, InputStream defaultConfig)
            throws IOException {
        if (clientConfig == null) {
            clientConfig = new ClientConfig(ca, serverCertificate, defaultConfig);
        }
        return clientConfig;
    }


    public static ClientConfig getInstance(CA ca, ServerCertificate serverCertificate)
            throws IOException {
        if (clientConfig == null) {
            clientConfig = new ClientConfig(ca, serverCertificate, null);
        }
        return clientConfig;
    }


    public static ClientConfig getInstance() throws IOException {
        if (clientConfig == null) {
            throw new IOException("Needs to be initialized with 'getInstance (CA ca, ServerCertificate serverCertificate, ServerCertificate signerCertificate)' first");
        }
        return clientConfig;
    }


    private void putConfigJson(InputStream defaultConfig) throws IOException {
        File fileLocation = Utils.findConfigFile("config.json");
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
        clientConfigModel = ClientConfigModel.deserialize(json);
        Map<String,String> remotekeystore = clientConfigModel.getRemotekeystore();
        remotekeystore.put(Constants.ca, ca.getCaCertificatePEM());
        try {
            remotekeystore.put(Constants.serverCert, serverCertificate.getServerCertificatePEM());
        } catch (CertificateEncodingException | IOException e) {
            logger.warn(e.getMessage());
        }
        clientConfigModel.setRemotekeystore(remotekeystore);

        Map<String, String> keyAlg = clientConfigModel.getKeyAlg();
        keyAlg.put("sign", configuration.getConfig().getProperty(Constants.prop_js_sign));
        keyAlg.put("hash", configuration.getConfig().getProperty(Constants.prop_js_hash));
        clientConfigModel.setKeyAlg(keyAlg);
    }


    public static ClientConfig getServerConfig() {

        return clientConfig;
    }


    public String getConfig()
            throws JsonProcessingException {

        return new String(clientConfigModel.serialize());
    }

    public static ClientConfigModel createDefaultConfig() throws IOException {
        String json = "{\n" +
                "  \"config\": {\n" +
                "    \"same_enc_sign_cert\": true,\n" +
                "    \"keyAlg\": {\n" +
                "      \"hash\": \"SHA-256\",\n" +
                "      \"sign\": \"RSASSA-PKCS1-V1_5\",\n" +
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
        return ClientConfigModel.deserialize(jsonStream);
    }

}
