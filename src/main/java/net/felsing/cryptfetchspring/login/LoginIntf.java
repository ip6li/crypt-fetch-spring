package net.felsing.cryptfetchspring.login;

import org.bouncycastle.cms.CMSException;

import java.io.IOException;
import java.util.Map;

public interface LoginIntf {

    Map<String, String> login (String cms) throws IOException, CMSException;

}
