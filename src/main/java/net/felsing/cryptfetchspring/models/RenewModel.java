package net.felsing.cryptfetchspring.models;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonRootName;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.nio.charset.StandardCharsets;


@JsonRootName(value = "RenewModel")
public class RenewModel implements PayloadModelIntf {
    private final String certificate;

    @JsonCreator
    public RenewModel(@JsonProperty("certificate") String certificate) {

        this.certificate = certificate;
    }

    public String getCertificate () { return certificate; }

    @Override
    public byte[] serialize() throws JsonProcessingException {
        ObjectMapper om = new ObjectMapper();
        return om.writeValueAsString(this).getBytes(StandardCharsets.UTF_8);
    }

    public static RenewModel deserialize(byte[] json) throws JsonProcessingException {
        ObjectMapper om = new ObjectMapper();
        return om.readerFor(RenewModel.class).readValue(new String(json));
    }
}

