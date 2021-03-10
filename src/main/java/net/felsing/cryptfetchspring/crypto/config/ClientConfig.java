package net.felsing.cryptfetchspring.crypto.config;

import com.fasterxml.jackson.core.JsonProcessingException;
import net.felsing.cryptfetchspring.crypto.certs.CA;
import net.felsing.cryptfetchspring.crypto.certs.ServerCertificate;
import net.felsing.cryptfetchspring.crypto.util.LogEngine;

import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.util.Map;


/*************************************************************************************************************
 * Handles configuration items needed by service consumers
 *************************************************************************************************************/
public class ClientConfig {
    private static final LogEngine logger = LogEngine.getLogger(ClientConfig.class);

    private final ServerCertificate serverCertificate;
    private final CA ca;
    private static ClientConfig clientConfig = null;
    private static ClientConfigModel clientConfigModel;
    private static final Configuration configuration = new Configuration();



    private ClientConfig(CA ca, ServerCertificate serverCertificate) {
        this.ca = ca;
        this.serverCertificate = serverCertificate;
        readConfiguration();
    }


    public static ClientConfig getInstance(CA ca, ServerCertificate serverCertificate)
            throws IOException {
        if (clientConfig == null) {
            clientConfig = new ClientConfig(ca, serverCertificate);
        }
        return clientConfig;
    }


    public static ClientConfig getInstance() throws IOException {
        if (clientConfig == null) {
            throw new IOException("Needs to be initialized with 'getInstance (CA ca, ServerCertificate serverCertificate, ServerCertificate signerCertificate)' first");
        }
        return clientConfig;
    }


    private void readConfiguration() {
        clientConfigModel = new ClientConfigModel();
        Map<String,String> remotekeystore = clientConfigModel.getRemotekeystore();
        remotekeystore.put(Constants.ca, ca.getCaCertificatePEM());
        try {
            remotekeystore.put(Constants.serverCert, serverCertificate.getServerCertificatePEM());
        } catch (CertificateEncodingException | IOException e) {
            logger.warn(e.getMessage());
        }
        clientConfigModel.setRemotekeystore(remotekeystore);

        logger.info(String.format("readConfiguration: %s", configuration.getConfig().getProperty(Constants.prop_js_same_enc_sign_cert)));
        clientConfigModel.setSame_enc_sign_cert(
                Boolean.parseBoolean(configuration.getConfig().getProperty(Constants.prop_js_same_enc_sign_cert))
        );
        clientConfigModel.setAuthURL(configuration.getConfig().getProperty(Constants.prop_js_authURL));
        clientConfigModel.setRenewURL(configuration.getConfig().getProperty(Constants.prop_js_renewURL));
        clientConfigModel.setMessageURL(configuration.getConfig().getProperty(Constants.prop_js_messageURL));

        Map<String, String> keyAlg = clientConfigModel.getKeyAlg();
        keyAlg.put("sign", configuration.getConfig().getProperty(Constants.prop_js_sign));
        keyAlg.put("hash", configuration.getConfig().getProperty(Constants.prop_js_hash));
        keyAlg.put("modulusLength", configuration.getConfig().getProperty(Constants.prop_js_modulusLength));
        clientConfigModel.setKeyAlg(keyAlg);

        Map<String, String> encAlg = clientConfigModel.getEncAlg();
        encAlg.put("name", configuration.getConfig().getProperty(Constants.prop_js_enc_name));
        encAlg.put("length", configuration.getConfig().getProperty(Constants.prop_js_enc_length));
        clientConfigModel.setEncAlg(encAlg);
    }


    public static ClientConfig getServerConfig() {

        return clientConfig;
    }


    public String getConfig()
            throws JsonProcessingException {

        return new String(clientConfigModel.serialize());
    }

}
