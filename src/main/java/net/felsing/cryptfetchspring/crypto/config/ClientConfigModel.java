package net.felsing.cryptfetchspring.crypto.config;

import com.fasterxml.jackson.annotation.*;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

@JsonRootName(value = "config")
public class ClientConfigModel implements Serializable {

    private boolean same_enc_sign_cert;
    private Map<String, String> keyAlg;
    private Map<String, String> encAlg;
    private Map<String, String> remotekeystore;
    private String authURL;
    private String messageURL;
    private String renewURL;

    @JsonCreator
    public ClientConfigModel(
            @JsonProperty("same_enc_sign_cert") boolean same_enc_sign_cert,
            @JsonProperty("keyAlg") Map<String, String> keyAlg,
            @JsonProperty("encAlg") Map<String, String> encAlg,
            @JsonProperty("authURL") String authURL,
            @JsonProperty("messageURL") String messageURL,
            @JsonProperty("renewURL") String renewURL,
            @JsonProperty("remotekeystore") Map<String,String> remotekeystore
            ) {
        this.same_enc_sign_cert = same_enc_sign_cert;
        this.keyAlg = keyAlg;
        this.encAlg = encAlg;
        this.authURL = authURL;
        this.messageURL = messageURL;
        this.renewURL = renewURL;
        this.remotekeystore = remotekeystore;
    }

    @JsonGetter
    public boolean isSame_enc_sign_cert() {
        return same_enc_sign_cert;
    }

    @JsonGetter
    public Map<String, String> getKeyAlg() {
        return keyAlg;
    }

    @JsonGetter
    public Map<String, String> getEncAlg() {
        return encAlg;
    }

    @JsonGetter
    public String getAuthURL() {
        return authURL;
    }

    @JsonGetter
    public String getMessageURL() {
        return messageURL;
    }

    @JsonGetter
    public String getRenewURL() {
        return renewURL;
    }

    @JsonGetter
    public Map<String, String> getRemotekeystore() {
        return remotekeystore;
    }

    @JsonSetter
    public void setKeyAlg(Map<String,String> keyAlg) {
        this.keyAlg = keyAlg;
    }

    public void setRemotekeystore(Map<String, String> remotekeystore) {
        this.remotekeystore = remotekeystore;
    }

    public byte[] serialize() throws JsonProcessingException {
        ObjectMapper mapper = new ObjectMapper();
        mapper.enable(SerializationFeature.WRAP_ROOT_VALUE);
        return mapper.writeValueAsString(this).getBytes(StandardCharsets.UTF_8);
    }

    public static ClientConfigModel deserialize(InputStream json) throws IOException {
        ObjectMapper om = new ObjectMapper();
        om.enable(DeserializationFeature.UNWRAP_ROOT_VALUE);
        return om.readerFor(ClientConfigModel.class).readValue(json);
    }
}
