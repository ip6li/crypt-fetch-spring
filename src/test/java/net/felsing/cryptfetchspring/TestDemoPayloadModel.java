package net.felsing.cryptfetchspring;

import com.fasterxml.jackson.core.JsonProcessingException;
import net.felsing.cryptfetchspring.models.PayloadDemoModel;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Map;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TestDemoPayloadModel {

    @Test
    void test() throws JsonProcessingException {
        final String json = "{\"mapWithStrings\":{\"foo\":\"bar äöüÄÖÜß€\"},\"aBoolean\":true,\"aString\":\"Made in Germany: äöüÄÖÜß€\"}";

        PayloadDemoModel payloadDemoModel = PayloadDemoModel.deserialize(json.getBytes(StandardCharsets.UTF_8));

        assertTrue(payloadDemoModel.getaBoolean());
        assertThat(payloadDemoModel.getaString(), containsString("Made in Germany: äöüÄÖÜß€"));
        Map<String,String> aMap = payloadDemoModel.getMapWithStrings();
        assertThat(aMap.get("foo"), containsString("bar äöüÄÖÜß€"));
    }
}
