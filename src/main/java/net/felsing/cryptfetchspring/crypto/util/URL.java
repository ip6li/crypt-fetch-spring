package net.felsing.cryptfetchspring.crypto.util;

import java.net.URI;
import java.net.URISyntaxException;

public class URL {

    public static String urlToPath (String rootPath, String srcUrl) throws URISyntaxException {
        URI src = new URI(srcUrl);
        if (!rootPath.matches(".*/$")) {
            rootPath=rootPath+"/";
        }

        String effectivePath;
        if (!src.isAbsolute()) {
            effectivePath = rootPath + src.getPath();
        } else {
            effectivePath = src.getPath();
        }

        return effectivePath.replaceAll("/{2,}", "/");
    }

} // class
