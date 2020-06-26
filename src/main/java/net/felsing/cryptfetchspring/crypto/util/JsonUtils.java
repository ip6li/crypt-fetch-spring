package net.felsing.cryptfetchspring.crypto.util;


import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.LoggerFactory;
import org.slf4j.Logger;
import java.io.*;
import java.util.HashMap;
import java.util.Map;
import org.apache.commons.io.serialization.ValidatingObjectInputStream;


public final class JsonUtils {
    private static final Logger logger = LoggerFactory.getLogger(JsonUtils.class);

    private JsonUtils () { }

    public static Map<?,?> json2map (String json) throws JsonProcessingException {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.readValue(json, new TypeReference<>(){});
    }

    public static String map2json (Map<?, ?> map) throws JsonProcessingException {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.writerWithDefaultPrettyPrinter().writeValueAsString(map);
    }

    public static Map<String, String> genError (String msg) {
        HashMap<String,String> errMsg = new HashMap<>();
        errMsg.put("error", msg);
        return errMsg;
    }

    public static String genErrorString (String msg) {
        try {
            return map2json(genError(msg));
        } catch (JsonProcessingException e) {
            logger.warn(e.getMessage());
            return null;
        }
    }

    public static byte[] serialize(Object obj) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ObjectOutputStream os = new ObjectOutputStream(out);
        os.writeObject(obj);
        return out.toByteArray();
    }

    public static Object deserialize(byte[] data) throws IOException, ClassNotFoundException {
        ByteArrayInputStream in = new ByteArrayInputStream(data);
        ObjectInputStream is = new ObjectInputStream(in);
        ValidatingObjectInputStream validator = new ValidatingObjectInputStream(is);
        validator.accept(Map.class, String.class);
        return validator.readObject();
    }

} // class
