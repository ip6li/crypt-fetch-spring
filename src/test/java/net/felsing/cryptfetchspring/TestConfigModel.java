package net.felsing.cryptfetchspring;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import net.felsing.cryptfetchspring.crypto.config.ConfigModel;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;

import static org.junit.jupiter.api.Assertions.assertEquals;


public class TestConfigModel {
    Logger logger = LoggerFactory.getLogger(TestConfigModel.class);
    private static ConfigModel configModel;

    @BeforeAll
    static void init() {
        HashMap<String, String> keyAlg = new HashMap<>();
        keyAlg.put("hash", "SHA-256");
        keyAlg.put("sign", "RSASSA-PKCS1-V1_5");
        keyAlg.put("signDISABLED", "RSA-PSS");
        keyAlg.put("modulusLength", "2048");

        HashMap<String, String> encAlg = new HashMap<>();
        encAlg.put("name", "AES-CBC");
        encAlg.put("length", "256");

        HashMap<String, String> remotekeystore = new HashMap<>();
        //remotekeystore.put("key", "value");

        configModel = new ConfigModel(
                true,
                keyAlg,
                encAlg,
                "http://127.0.0.1:8080/login",
                "http://127.0.0.1:8080/message",
                "http://127.0.0.1:8080/renew",
                remotekeystore
        );
    }

    @Test
    void testGetJson() throws JsonProcessingException {
        String json = configModel2Json();
        logger.info(json);

        ConfigModel configModel1 = json2configModel(json);
        assertEquals("SHA-256", configModel1.getKeyAlg().get("hash"));
    }


    private String configModel2Json() throws JsonProcessingException {
        ObjectMapper mapper = new ObjectMapper();
        mapper.enable(SerializationFeature.WRAP_ROOT_VALUE);
        return mapper.writeValueAsString(configModel);
    }

    private ConfigModel json2configModel(String json) throws JsonProcessingException {
        ObjectMapper om = new ObjectMapper();
        om.enable(DeserializationFeature.UNWRAP_ROOT_VALUE);
        return om
                .readerFor(ConfigModel.class)
                .readValue(json);
    }

}
