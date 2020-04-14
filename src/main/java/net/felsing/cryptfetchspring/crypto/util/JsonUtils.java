package net.felsing.cryptfetchspring.crypto.util;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.*;
import java.util.HashMap;
import java.util.Map;


public final class JsonUtils {
    private static final Logger logger = LogManager.getLogger(JsonUtils.class);

    private JsonUtils () { }

    public static HashMap<?,?> json2map (String json) throws JsonProcessingException {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.readValue(json, new TypeReference<>(){});
    }

    public static String map2json (Map<?, ?> map) throws JsonProcessingException {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.writerWithDefaultPrettyPrinter().writeValueAsString(map);
    }

    public static HashMap<String, String> genError (String msg) {
        HashMap<String,String> errMsg = new HashMap<>();
        errMsg.put("error", msg);
        return errMsg;
    }

    public static String genErrorString (String msg) {
        try {
            return map2json(genError(msg));
        } catch (JsonProcessingException e) {
            logger.warn(e);
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
        return is.readObject();
    }

} // class
