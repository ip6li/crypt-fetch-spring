package net.felsing.cryptfetchspring;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonGetter;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonRootName;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import java.io.Serializable;
import java.nio.charset.StandardCharsets;

@JsonRootName(value = "test")
public class TestClass implements Serializable {
    private String s1;
    private String s2;

    public TestClass() {}

    @JsonCreator
    public TestClass(
            @JsonProperty("s1") String s1,
            @JsonProperty("s2") String s2
    ) {
        this.s1 = s1;
        this.s2 = s2;
    }

    @JsonGetter
    public String getS1() {
        return s1;
    }

    public void setS1(String s1) {
        this.s1 = s1;
    }

    @JsonGetter
    public String getS2() {
        return s2;
    }

    public void setS2(String s2) {
        this.s2 = s2;
    }

    @Override
    public boolean equals(Object o) {
        if (o instanceof TestClass) {
            TestClass pair = (TestClass) o;
            return (this.s1.equals(pair.s1) && this.s2.equals(pair.s2));
        } else
            return false;
    }

    public byte[] serializes() throws JsonProcessingException {
        ObjectMapper mapper = new ObjectMapper();
        mapper.enable(SerializationFeature.WRAP_ROOT_VALUE);
        return mapper.writeValueAsString(this).getBytes(StandardCharsets.UTF_8);
    }

    public static TestClass deserialize(byte[] json) throws JsonProcessingException {
        ObjectMapper om = new ObjectMapper();
        om.enable(DeserializationFeature.UNWRAP_ROOT_VALUE);
        return om.readerFor(TestClass.class).readValue(new String(json));
    }
}
