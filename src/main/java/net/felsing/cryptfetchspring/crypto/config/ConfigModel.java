package net.felsing.cryptfetchspring.crypto.config;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonGetter;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonRootName;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;

@JsonRootName(value = "config")
public class ConfigModel implements Serializable {

    private boolean same_enc_sign_cert;
    private HashMap<String, String> keyAlg;
    private HashMap<String, String> encAlg;
    private HashMap<String, String> remotekeystore;
    private String authURL;
    private String messageURL;
    private String renewURL;

    @JsonCreator
    public ConfigModel (
            @JsonProperty("same_enc_sign_cert") boolean same_enc_sign_cert,
            @JsonProperty("keyAlg") HashMap<String, String> keyAlg,
            @JsonProperty("encAlg") HashMap<String, String> encAlg,
            @JsonProperty("authURL") String authURL,
            @JsonProperty("messageURL") String messageURL,
            @JsonProperty("renewURL") String renewURL,
            @JsonProperty("remotekeystore") HashMap<String,String> remotekeystore
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
    public HashMap<String, String> getKeyAlg() {
        return keyAlg;
    }

    @JsonGetter
    public HashMap<String, String> getEncAlg() {
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
    public HashMap<String, String> getRemotekeystore() {
        return remotekeystore;
    }

    public void setRemotekeystore(HashMap<String, String> remotekeystore) {
        this.remotekeystore = remotekeystore;
    }

    public byte[] serialize() throws JsonProcessingException {
        ObjectMapper mapper = new ObjectMapper();
        mapper.enable(SerializationFeature.WRAP_ROOT_VALUE);
        return mapper.writeValueAsString(this).getBytes(StandardCharsets.UTF_8);
    }

    public static ConfigModel deserialize(InputStream json) throws IOException {
        ObjectMapper om = new ObjectMapper();
        om.enable(DeserializationFeature.UNWRAP_ROOT_VALUE);
        return om.readerFor(ConfigModel.class).readValue(json);
    }
}
