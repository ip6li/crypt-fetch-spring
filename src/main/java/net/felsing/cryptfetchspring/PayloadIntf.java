package net.felsing.cryptfetchspring;

import net.felsing.cryptfetchspring.crypto.certs.CmsSign;

import java.io.IOException;
import java.util.Map;

public interface PayloadIntf {

    Map<?,?> doPayload (CmsSign.Result plainTextContent) throws IOException;

}
