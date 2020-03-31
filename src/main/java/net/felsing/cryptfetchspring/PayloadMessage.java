package net.felsing.cryptfetchspring;

import net.felsing.cryptfetchspring.crypto.certs.CmsSign;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import java.util.HashMap;
import java.util.Map;


public class PayloadMessage implements PayloadIntf {
    private static Logger logger = LogManager.getLogger(MessageHandler.class);

    private PayloadMessage () {}

    public static PayloadMessage getInstance() {

        return new PayloadMessage();
    }

    @Override
    public Map<String,String> doPayload (CmsSign.Result plainTextContent) {
        logger.info("[doPayload] request: {}", new String(plainTextContent.getContent()));
        HashMap<String,String> plainTextResponse = new HashMap<>();
        plainTextResponse.put("foo", "bar äöüÄÖÜß€");
        return plainTextResponse;
    }

}
