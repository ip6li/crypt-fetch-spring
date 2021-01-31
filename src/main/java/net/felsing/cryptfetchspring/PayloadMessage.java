package net.felsing.cryptfetchspring;

import com.fasterxml.jackson.core.JsonProcessingException;
import net.felsing.cryptfetchspring.crypto.certs.CmsSign;
import net.felsing.cryptfetchspring.models.PayloadDemoModel;
import net.felsing.cryptfetchspring.models.PayloadModelIntf;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;


/*
Probably you want to implement your own class here to handle your payload.
Do not forget to provide your class in CryptFetchSpringApplication.
 */
public class PayloadMessage implements PayloadIntf {
    private static final Logger logger = LoggerFactory.getLogger(PayloadMessage.class);

    private PayloadMessage () {}

    public static PayloadMessage getInstance() {

        return new PayloadMessage();
    }

    @Override
    public byte[] doPayload (CmsSign.Result plainTextContent) throws JsonProcessingException {
        if (logger.isInfoEnabled()) {
            logger.info(String.format("[doPayload] request: %s",
                    new String(plainTextContent.getContent(), StandardCharsets.UTF_8)));
        }

        HashMap<String,String> testMap = new HashMap<>();
        testMap.put("foo", "bar äöüÄÖÜß€");
        PayloadModelIntf payloadModel = new PayloadDemoModel(
                testMap,
                true,
                "Made in Germany: äöüÄÖÜß€"
        );
        return payloadModel.serialize();
    }

}
