package net.felsing.cryptfetchspring;

import com.fasterxml.jackson.core.JsonProcessingException;
import net.felsing.cryptfetchspring.crypto.certs.CmsSign;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;


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

        PayloadModel payloadModel = new PayloadModel();
        payloadModel.setaBoolean(true);
        payloadModel.setaString("Made in Germany: äöüÄÖÜß€");
        payloadModel.put("foo", "bar äöüÄÖÜß€");
        return payloadModel.serialize();
    }

}
