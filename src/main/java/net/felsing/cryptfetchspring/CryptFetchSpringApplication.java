package net.felsing.cryptfetchspring;

import com.fasterxml.jackson.core.JsonProcessingException;
import net.felsing.cryptfetchspring.crypto.certs.CA;
import net.felsing.cryptfetchspring.crypto.util.JsonUtils;
import net.felsing.cryptfetchspring.login.Login;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.ServletContextAware;
import javax.annotation.PostConstruct;
import javax.servlet.ServletContext;
import java.util.HashMap;
import java.util.Map;


@SpringBootApplication
@RestController
public class CryptFetchSpringApplication implements ServletContextAware {
    private static Logger logger = LogManager.getLogger(CryptFetchSpringApplication.class);

    private static ServerConfig serverConfig;
    private ServletContext servletContext;

    public static void main(String[] args) {
        SpringApplication application = new SpringApplication(CryptFetchSpringApplication.class);
        application.run(args);
    }


    @PostConstruct
    public void addInitHooks() {
        try {
            String absolutePath = servletContext.getRealPath("resources");
            logger.info("[addInitHooks] absolutePath: " + absolutePath);
            CA ca = CryptInit.getInstance("./");
            serverConfig = ServerConfig.getInstance(ca, CryptInit.getServerCertificate(), CryptInit.getSignerCertificate());
        } catch (Exception e) {
            logger.error(e);
        }
    }


    @RequestMapping(value = "/config", method = RequestMethod.GET)
    public Map<String, ?> getConfig() {
        // Deliver server/ca certificate and urls for further operations
        return serverConfig.getConfig();
    }


    @RequestMapping(value = "/login", method = RequestMethod.POST)
    public Map<String, String> login(@RequestBody String request) {
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
    public String renew(@RequestBody String request) {
        MessageHandler messageHandler = MessageHandler.getInstance(
                CryptInit.getServerCertificate().getServerKeyPair(),
                CryptInit.getServerCertificate().getServerCertificate(),
                CryptInit.getCa().getCaX509Certificate());

        try {
            return messageHandler.doRequest(request, PayloadRenew.getInstance());
        } catch (Exception e) {
            logger.warn(e);
        }

        String returnValue;
        try {
            returnValue = JsonUtils.map2json((Map<?, ?>) new HashMap<>().put("error", "renew failed"));
        } catch (JsonProcessingException e) {
            returnValue = "error";
        }
        return returnValue;
    }


    @RequestMapping(value = "/message", method = RequestMethod.POST)
    public String message(@RequestBody String request) {
        // Get encrypted request und put encrypted response
        MessageHandler messageHandler = MessageHandler.getInstance(
                CryptInit.getServerCertificate().getServerKeyPair(),
                CryptInit.getServerCertificate().getServerCertificate(),
                CryptInit.getCa().getCaX509Certificate());

        try {
            return messageHandler.doRequest(request, PayloadMessage.getInstance());
        } catch (Exception e) {
            logger.warn(e);
        }

        String returnValue;
        try {
            returnValue = JsonUtils.map2json((Map<?, ?>) new HashMap<>().put("error", "message failed"));
        } catch (JsonProcessingException e) {
            returnValue = "error";
        }
        return returnValue;
    }


    @RequestMapping(value = "/", method = RequestMethod.GET)
    public String getRoot() {
        //ToDo: Provide default communications
        return "getRoot()";
    }

    @Override
    public void setServletContext(ServletContext servletContext) {

        this.servletContext = servletContext;
    }
}
