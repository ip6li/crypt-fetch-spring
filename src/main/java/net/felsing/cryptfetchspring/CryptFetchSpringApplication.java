package net.felsing.cryptfetchspring;

import net.felsing.cryptfetchspring.crypto.certs.CA;
import net.felsing.cryptfetchspring.login.Login;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.cms.CMSException;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;


@SpringBootApplication
@RestController
public class CryptFetchSpringApplication {
    private static Logger logger = LogManager.getLogger(CryptFetchSpringApplication.class);
    private static ServerConfig serverConfig;


    public static void main(String[] args) {
        SpringApplication application = new SpringApplication(CryptFetchSpringApplication.class);
        addInitHooks(application);
        application.run(args);
    }


    private static void addInitHooks(SpringApplication application) {
        try {
            CA ca = CryptInit.getInstance("./");
            serverConfig = ServerConfig.getInstance(ca, CryptInit.getServerCertificate(), CryptInit.getSignerCertificate());
        } catch (Exception e) {
            logger.error(e);
        }
    }


    @RequestMapping(value = "/config", method = RequestMethod.GET)
    public Map<String, ?> getConfig() {
        //ToDo: Deliver server/ca certificate and urls for further operations
        return serverConfig.getConfig();
    }


    @RequestMapping(value = "/login", method = RequestMethod.POST)
    public Map login(@RequestBody String request) {
        // getCSR, verify credentials, if ok: sign CSR and return client certificate
        Login login = new Login();
        try {
            return login.login(request);
        } catch (Exception e) {
            logger.warn(e);
            HashMap<String, String> result = new HashMap<>();
            result.put("error", "Login failed");
            return result;
        }
    }


    @RequestMapping(value = "/renew", method = RequestMethod.POST)
    public String renew() {
        //ToDo: renew client certificate
        return "renew()";
    }


    @RequestMapping(value = "/message", method = RequestMethod.POST)
    public String message() {
        //ToDo: get encrypted request und put encrypted response
        return "message()";
    }


    @RequestMapping(value = "/", method = RequestMethod.GET)
    public String getRoot() {
        //ToDo: Provide default communications
        return "getRoot()";
    }

}
