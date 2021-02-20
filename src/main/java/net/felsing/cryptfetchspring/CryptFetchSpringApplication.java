package net.felsing.cryptfetchspring;

import com.fasterxml.jackson.core.JsonProcessingException;
import net.felsing.cryptfetchspring.crypto.certs.CA;
import net.felsing.cryptfetchspring.login.Login;
import net.felsing.cryptfetchspring.models.ErrorModel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.core.io.ClassPathResource;
import org.springframework.lang.NonNull;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.ServletContextAware;

import javax.annotation.PostConstruct;
import javax.servlet.ServletContext;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;


@SpringBootApplication
@RestController
public class CryptFetchSpringApplication implements ServletContextAware {
    private static final Logger logger = LoggerFactory.getLogger(CryptFetchSpringApplication.class);

    private static final String ERROR = "error";

    private static ServerConfig serverConfig;
    private ServletContext servletContext;

    @Value("${pki.path}")
    private String caRootPath;

    public static void main(String[] args) {
        SpringApplication application = new SpringApplication(CryptFetchSpringApplication.class);
        application.run(args);
    }


    private static void setServerConfig (CA ca) throws IOException {
        final String configJsonFile = "config.json";
        ClassPathResource resource = new ClassPathResource(configJsonFile);
        if(!resource.exists()){
            logger.info(String.format("%s file does not exist.", configJsonFile));
        }
        serverConfig = ServerConfig.getInstance(
                ca,
                CryptInit.getServerCertificate(),
                resource.getInputStream()
        );
    }


    @PostConstruct
    public void addInitHooks() {
        try {
            String absolutePath = servletContext.getRealPath("resources");
            if (logger.isInfoEnabled()) {
                logger.info(String.format("[addInitHooks] absolutePath: %s", absolutePath));
                logger.info(String.format("caRootPath: %s", caRootPath));
            }

            CA ca = CryptInit.getInstance(caRootPath);
            setServerConfig(ca);
        } catch (Exception e) {
            logger.error(String.format("addInitHooks: %s", e.getMessage()));
            e.printStackTrace();
        }
    }


    @GetMapping(value = "/config")
    public String getConfig() throws JsonProcessingException {
        // Deliver server/ca certificate and urls for further operations
        return serverConfig.getConfig();
    }


    @PostMapping(value = "/config")
    public String getConfigPost() throws JsonProcessingException {
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
            logger.warn(String.format("login: %s", e.getMessage()));
            HashMap<String, String> result = new HashMap<>();
            result.put(ERROR, "Login failed");
            return result;
        }
    }


    @PostMapping(value = "/renew")
    public String renew(@RequestBody String request) throws JsonProcessingException {
        MessageHandler messageHandler = MessageHandler.getInstance(
                CryptInit.getServerCertificate().getServerKeyPair(),
                CryptInit.getServerCertificate().getServerCertificate(),
                CryptInit.getCa().getCaX509Certificate());

        try {
            return messageHandler.doRequest(request, PayloadRenew.getInstance());
        } catch (Exception e) {
            logger.warn(String.format("renew: %s", e.getMessage()));
        }

        return new String(new ErrorModel("renew failed").serialize());
    }


    @PostMapping(value = "/message")
    public String message(@RequestBody String request) throws JsonProcessingException {
        // Get encrypted request und put encrypted response
        MessageHandler messageHandler = MessageHandler.getInstance(
                CryptInit.getServerCertificate().getServerKeyPair(),
                CryptInit.getServerCertificate().getServerCertificate(),
                CryptInit.getCa().getCaX509Certificate());

        try {
            // Insert you Payload handler class here vvvvvvvvvvvvvv
            return messageHandler.doRequest(request, PayloadMessage.getInstance());
        } catch (Exception e) {
            logger.warn(String.format("message: %s", e.getMessage()));
        }

        return new String(new ErrorModel("message failed").serialize());
    }


    @GetMapping(value = "/")
    public String getRoot() {
        //ToDo: Provide default communications
        return "getRoot();";
    }

    @Override
    public void setServletContext(@NonNull ServletContext servletContext) {

        this.servletContext = servletContext;
    }
}
