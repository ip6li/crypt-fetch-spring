package net.felsing.cryptfetchspring;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.Serializable;

public class TestClass implements Serializable {
    private String s1;
    private String s2;

    public String getS1() {
        return s1;
    }

    public void setS1(String s1) {
        this.s1 = s1;
    }

    public String getS2() {
        return s2;
    }

    public void setS2(String s2) {
        this.s2 = s2;
    }

    @Override
    public String toString() {
        JSONObject json = new JSONObject();
        try {
            json.put("s1", s1);
            json.put("s2", s2);
        } catch (JSONException e) {
            e.printStackTrace();
        }
        return json.toString();
    }

    @Override
    public boolean equals(Object o) {
        if (o instanceof TestClass) {
            TestClass pair = (TestClass) o;
            return (this.s1.equals(pair.s1) && this.s2.equals(pair.s2));
        } else
            return false;
    }
}
