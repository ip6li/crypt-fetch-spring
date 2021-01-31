package net.felsing.cryptfetchspring.login;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonRootName;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;

@JsonRootName(value = "credentials")
public class LoginModel {
    public static final String USERNAME = "username";
    public static final String PASSWORD = "password";
    public static final String CSR = "csr";

    private final HashMap<String, String> credentials = new HashMap<>();

    public LoginModel(
            @JsonProperty("username") String username,
            @JsonProperty("password") String password,
            @JsonProperty("csr") String csr
    ) {
        credentials.put(USERNAME, username);
        credentials.put(PASSWORD, password);
        credentials.put(CSR, csr);
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
