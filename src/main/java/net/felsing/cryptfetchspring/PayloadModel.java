package net.felsing.cryptfetchspring;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonRootName;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import net.felsing.cryptfetchspring.login.LoginModel;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;

@JsonRootName(value = "data")
public class PayloadModel {
    private HashMap<String, String> mapWithStrings = new HashMap<>();
    private boolean aBoolean;
    private String aString;

    public PayloadModel() {}

    public PayloadModel (
        @JsonProperty("mapWithStrings") HashMap<String,String> mapWithStrings,
        @JsonProperty("aBoolean") boolean  aBoolean,
        @JsonProperty("aString") String aString
    ) {
        this.mapWithStrings = mapWithStrings;
        this.aBoolean = aBoolean;
        this.aString = aString;
    }

    public void put (String k, String v) { mapWithStrings.put(k, v); }

    public boolean isaBoolean() {
        return aBoolean;
    }

    public void setaBoolean(boolean aBoolean) {
        this.aBoolean = aBoolean;
    }

    public String getaString() {
        return aString;
    }

    public void setaString(String aString) {
        this.aString = aString;
    }

    public HashMap<String, String> getMapWithStrings() {
        return mapWithStrings;
    }

    public void setMapWithStrings(HashMap<String, String> mapWithStrings) {
        this.mapWithStrings = mapWithStrings;
    }

    public byte[] serialize() throws JsonProcessingException {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.writeValueAsString(this).getBytes(StandardCharsets.UTF_8);
    }

    public static PayloadModel deserialize(byte[] json) throws JsonProcessingException {
        ObjectMapper om = new ObjectMapper();
        return om.readerFor(PayloadModel.class).readValue(new String(json));
    }
}
