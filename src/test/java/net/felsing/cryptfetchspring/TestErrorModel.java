package net.felsing.cryptfetchspring;

import com.fasterxml.jackson.core.JsonProcessingException;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class TestErrorModel {
    private static final Logger logger = LoggerFactory.getLogger(TestErrorModel.class);

    @Test
    void test() throws JsonProcessingException {
        final String msg = "Hello error";
        ErrorModel errorModel = new ErrorModel(msg);
        assertNotNull (errorModel);

        byte[] json = errorModel.serialize();
        logger.info(String.format("json: %s", new String(json)));
        assertThat(new String(json), containsString(msg));

        ErrorModel errorModel1 = ErrorModel.deserialize(json);
        assertThat(errorModel1.get(), containsString(msg));
    }
}
