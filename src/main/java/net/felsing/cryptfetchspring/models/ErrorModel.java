package net.felsing.cryptfetchspring.models;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonRootName;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.nio.charset.StandardCharsets;

@JsonRootName(value = "error")
public class ErrorModel {
    @JsonProperty
    private final String msg;

    @JsonCreator
    public ErrorModel (@JsonProperty("msg") String msg) {

        this.msg = msg;
    }

    public String get () { return msg; }

    public byte[] serialize() throws JsonProcessingException {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.writeValueAsString(this).getBytes(StandardCharsets.UTF_8);
    }

    public static ErrorModel deserialize(byte[] json) throws JsonProcessingException {
        ObjectMapper om = new ObjectMapper();
        return om.readerFor(ErrorModel.class).readValue(new String(json));
    }

}
