package net.felsing.cryptfetchspring;

import com.fasterxml.jackson.core.JsonProcessingException;
import net.felsing.cryptfetchspring.crypto.certs.CA;
import net.felsing.cryptfetchspring.crypto.util.JsonUtils;
import net.felsing.cryptfetchspring.login.Login;
import org.slf4j.LoggerFactory;
import org.slf4j.Logger;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.context.ServletContextAware;
import javax.annotation.PostConstruct;
import javax.servlet.ServletContext;
import java.util.HashMap;
import java.util.Map;


@SpringBootApplication
@RestController
public class CryptFetchSpringApplication implements ServletContextAware {
    private static final Logger logger = LoggerFactory.getLogger(CryptFetchSpringApplication.class);

    private static final String ERROR = "error";

    private static ServerConfig serverConfig;
    private ServletContext servletContext;

    public static void main(String[] args) {
        SpringApplication application = new SpringApplication(CryptFetchSpringApplication.class);
        application.run(args);
    }


    private static void setServerConfig (CA ca) {
        serverConfig = ServerConfig.getInstance(
                ca,
                CryptInit.getServerCertificate(),
                CryptInit.getSignerCertificate()
        );
    }


    @PostConstruct
    public void addInitHooks() {
        try {
            String absolutePath = servletContext.getRealPath("resources");
            if (logger.isInfoEnabled()) {
                logger.info(String.format("[addInitHooks] absolutePath: %s", absolutePath));
            }
            CA ca = CryptInit.getInstance("./");
            setServerConfig(ca);
        } catch (Exception e) {
            logger.error(e.getMessage());
        }
    }


    @GetMapping(value = "/config")
    public Map<String, ?> getConfig() {
        // Deliver server/ca certificate and urls for further operations
        return serverConfig.getConfig();
    }


    @PostMapping(value = "/login")
    public Map<String, String> login(@RequestBody String request) {
        // getCSR, verify credentials, if ok: sign CSR and return client certificate
        Login login = new Login();
        try {
            return login.login(request);
        } catch (Exception e) {
            logger.warn(e.getMessage());
            HashMap<String, String> result = new HashMap<>();
            result.put(ERROR, "Login failed");
            return result;
        }
    }


    @PostMapping(value = "/renew")
    public String renew(@RequestBody String request) {
        MessageHandler messageHandler = MessageHandler.getInstance(
                CryptInit.getServerCertificate().getServerKeyPair(),
                CryptInit.getServerCertificate().getServerCertificate(),
                CryptInit.getCa().getCaX509Certificate());

        try {
            return messageHandler.doRequest(request, PayloadRenew.getInstance());
        } catch (Exception e) {
            logger.warn(e.getMessage());
        }

        String returnValue;
        try {
            returnValue = JsonUtils.map2json((Map<?, ?>) new HashMap<>().put(ERROR, "renew failed"));
        } catch (JsonProcessingException e) {
            returnValue = ERROR;
        }
        return returnValue;
    }


    @PostMapping(value = "/message")
    public String message(@RequestBody String request) {
        // Get encrypted request und put encrypted response
        MessageHandler messageHandler = MessageHandler.getInstance(
                CryptInit.getServerCertificate().getServerKeyPair(),
                CryptInit.getServerCertificate().getServerCertificate(),
                CryptInit.getCa().getCaX509Certificate());

        try {
            return messageHandler.doRequest(request, PayloadMessage.getInstance());
        } catch (Exception e) {
            logger.warn(e.getMessage());
        }

        String returnValue;
        try {
            returnValue = JsonUtils.map2json((Map<?, ?>) new HashMap<>().put(ERROR, "message failed"));
        } catch (JsonProcessingException e) {
            returnValue = ERROR;
        }
        return returnValue;
    }


    @GetMapping(value = "/")
    public String getRoot() {
        //ToDo: Provide default communications
        return "getRoot()";
    }

    @Override
    public void setServletContext(ServletContext servletContext) {

        this.servletContext = servletContext;
    }
}
