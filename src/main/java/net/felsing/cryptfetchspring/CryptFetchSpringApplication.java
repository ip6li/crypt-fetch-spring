package net.felsing.cryptfetchspring;

import net.felsing.cryptfetchspring.crypto.certs.CA;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;


@SpringBootApplication
public class CryptFetchSpringApplication {
    private static Logger logger = LogManager.getLogger(CryptFetchSpringApplication.class);

    private static CA ca;

    public static void main(String[] args) {
        SpringApplication application = new SpringApplication(CryptFetchSpringApplication.class);
        addInitHooks(application);
        application.run(args);
    }

    private static void addInitHooks(SpringApplication application) {
        try {
            ca = CryptInit.getInstance("./");
        } catch (Exception e) {
            logger.error(e);
        }
    }

    private static String getCAcertificate () {
        return ca.getCaCertificatePEM();
    }

}
