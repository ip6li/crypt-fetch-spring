package net.felsing.cryptfetchspring.models;

import com.fasterxml.jackson.annotation.JsonGetter;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonRootName;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

@JsonRootName(value = "data")
public class PayloadDemoModel implements PayloadModelIntf {
    private Map<String, String> mapWithStrings = new HashMap<>();
    private boolean aBoolean;
    private String aString;

    public PayloadDemoModel(
        @JsonProperty("mapWithStrings") Map<String,String> mapWithStrings,
        @JsonProperty("aBoolean") boolean  aBoolean,
        @JsonProperty("aString") String aString
    ) {
        this.mapWithStrings = mapWithStrings;
        this.aBoolean = aBoolean;
        this.aString = aString;
    }

    public void put (String k, String v) { mapWithStrings.put(k, v); }

    @JsonGetter
    public boolean getaBoolean() {
        return aBoolean;
    }

    public void setaBoolean(boolean aBoolean) {
        this.aBoolean = aBoolean;
    }

    @JsonGetter
    public String getaString() {
        return aString;
    }

    public void setaString(String aString) {
        this.aString = aString;
    }

    @JsonGetter
    public Map<String, String> getMapWithStrings() {
        return mapWithStrings;
    }

    public void setMapWithStrings(Map<String, String> mapWithStrings) {
        this.mapWithStrings = mapWithStrings;
    }

    @Override
    public byte[] serialize() throws JsonProcessingException {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.writeValueAsString(this).getBytes(StandardCharsets.UTF_8);
    }

    public static PayloadDemoModel deserialize(byte[] json) throws JsonProcessingException {
        ObjectMapper om = new ObjectMapper();
        return om.readerFor(PayloadDemoModel.class).readValue(new String(json));
    }
}
