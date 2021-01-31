package net.felsing.cryptfetchspring.models;

import com.fasterxml.jackson.core.JsonProcessingException;

import java.io.Serializable;

public interface PayloadModelIntf extends Serializable {

    byte[] serialize() throws JsonProcessingException;
}
