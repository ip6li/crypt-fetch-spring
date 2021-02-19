package net.felsing.cryptfetchspring.login;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonRootName;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;

@JsonRootName(value = "credentials")
public class LoginModel {
    public static final String FIELD_USERNAME = "username";
    public static final String FIELD_PASSWORD = "password";
    public static final String FIELD_CSR = "csr";

    private final HashMap<String, String> credentials = new HashMap<>();

    public LoginModel(
            @JsonProperty(FIELD_USERNAME) String username,
            @JsonProperty(FIELD_PASSWORD) String password,
            @JsonProperty("csr") String csr
    ) {
        credentials.put(FIELD_USERNAME, username);
        credentials.put(FIELD_PASSWORD, password);
        credentials.put(FIELD_CSR, csr);
    }

    public HashMap<String, String> getCredentials() { return credentials; }

    public byte[] serialize() throws JsonProcessingException {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.writeValueAsString(this).getBytes(StandardCharsets.UTF_8);
    }

    public static LoginModel deserialize(byte[] json) throws JsonProcessingException {
        ObjectMapper om = new ObjectMapper();
        return om.readerFor(LoginModel.class).readValue(new String(json));
    }
}
