package net.felsing.cryptfetchspring;

import net.felsing.cryptfetchspring.crypto.certs.CmsSign;

import java.io.IOException;
import java.util.Map;

public interface PayloadIntf {

    byte[] doPayload (CmsSign.Result plainTextContent) throws IOException;

}
