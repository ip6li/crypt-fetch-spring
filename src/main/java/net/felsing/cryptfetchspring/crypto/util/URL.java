package net.felsing.cryptfetchspring.crypto.util;

import java.io.File;
import java.net.URI;
import java.net.URISyntaxException;

public class URL {

    private URL () {}

    public static String urlToPath (String rootPath, String srcUrl) throws URISyntaxException {
        URI src = new URI(srcUrl);
        String effectivePath;
        if (!src.isAbsolute()) {
            effectivePath = new File(rootPath, src.getPath()).getAbsolutePath();
        } else {
            effectivePath = src.getPath();
        }

        return effectivePath.replaceAll("/{2,}", "/");
    }

} // class
