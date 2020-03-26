package net.felsing.cryptfetchspring;

import net.felsing.cryptfetchspring.crypto.certs.CA;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.util.HashMap;
import java.util.Map;


@SpringBootApplication
@RestController
public class CryptFetchSpringApplication {
    private static Logger logger = LogManager.getLogger(CryptFetchSpringApplication.class);

    private static CA ca;
    private static ServerConfig serverConfig;


    public static void main(String[] args) {
        SpringApplication application = new SpringApplication(CryptFetchSpringApplication.class);
        addInitHooks(application);
        application.run(args);
    }

    private static void addInitHooks(SpringApplication application) {
        try {
            ca = CryptInit.getInstance("./");
            serverConfig = ServerConfig.getInstance(ca, CryptInit.getServerCertificate(), CryptInit.getSignerCertificate());
        } catch (Exception e) {
            logger.error(e);
        }
    }

    @RequestMapping(value = "/config")
    public Map<String, String> getConfig() {
        //ToDo: Deliver server/ca certificate and urls for further operations
        return ServerConfig.getServerConfig().getConfig();
    }

    @RequestMapping(value = "/login")
    public String login() {
        //ToDo: getCSR, verify credentials, if ok: sign CSR and return client certificate
        return "login()";
    }

    @RequestMapping(value = "/")
    public String getRoot() {
        //ToDo: Provide default communications
        return "getRoot()";
    }

}
