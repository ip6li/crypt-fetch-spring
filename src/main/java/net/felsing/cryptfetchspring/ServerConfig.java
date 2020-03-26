package net.felsing.cryptfetchspring;

import net.felsing.cryptfetchspring.crypto.certs.CA;
import net.felsing.cryptfetchspring.crypto.certs.ServerCertificate;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.util.HashMap;
import java.util.Map;


public class ServerConfig {
    private static Logger logger = LogManager.getLogger(ServerConfig.class);

    private ServerCertificate serverCertificate, signerCertificate;
    private CA ca;
    private static ServerConfig serverConfig = null;

    private ServerConfig (CA ca, ServerCertificate serverCertificate, ServerCertificate signerCertificate) {
        this.ca = ca;
        this.serverCertificate = serverCertificate;
        this.signerCertificate = signerCertificate;
    }

    public static ServerConfig getInstance (CA ca, ServerCertificate serverCertificate, ServerCertificate signerCertificate) {
        if (serverConfig == null) {
            serverConfig = new ServerConfig(ca, serverCertificate, signerCertificate);
        }
        return serverConfig;
    }

    public static ServerConfig getServerConfig () {

        return serverConfig;
    }

    public Map<String, String> getConfig() {
        //ToDo: Deliver server/ca certificate and urls for further operations
        HashMap<String, String> map = new HashMap<>();
        map.put("ca", ca.getCaCertificatePEM());
        try {
            map.put("serverCertificate", serverCertificate.getServerCertificatePEM());
        } catch (CertificateEncodingException | IOException e) {
            logger.warn(e);
        }
        try {
            map.put("serverSignerCertificate", signerCertificate.getServerCertificatePEM());
        } catch (CertificateEncodingException| IOException e) {
            logger.warn(e);
        }
        return map;
    }

}
