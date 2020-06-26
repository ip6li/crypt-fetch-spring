package net.felsing.cryptfetchspring;

import net.felsing.cryptfetchspring.crypto.certs.CmsSign;
import org.slf4j.LoggerFactory;
import org.slf4j.Logger;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;


public class PayloadMessage implements PayloadIntf {
    private static final Logger logger = LoggerFactory.getLogger(PayloadMessage.class);

    private PayloadMessage () {}

    public static PayloadMessage getInstance() {

        return new PayloadMessage();
    }

    @Override
    public Map<String,String> doPayload (CmsSign.Result plainTextContent) {
        if (logger.isInfoEnabled()) {
            logger.info(String.format("[doPayload] request: %s",
                    new String(plainTextContent.getContent(), StandardCharsets.UTF_8)));
        }
        HashMap<String,String> plainTextResponse = new HashMap<>();
        plainTextResponse.put("foo", "bar äöüÄÖÜß€");
        return plainTextResponse;
    }

}
