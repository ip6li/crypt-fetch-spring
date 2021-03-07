package net.felsing.cryptfetchspring.crypto.util;

import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class Utils {
    private static final LogEngine logger = LogEngine.getLogger(Utils.class);

    private Utils() {
    }

    private static List<String> buildPossibleFileLocations(String filename) {
        final ArrayList<String> fileLocations = new ArrayList<>();
        try {
            Resource configJsonFile = new ClassPathResource(filename);
            File f = configJsonFile.getFile();
            if (f.exists()) {
                fileLocations.add(f.getAbsolutePath());
            }
        } catch (IOException e) {
            // do nothing
        }
        fileLocations.add("./" + filename);
        fileLocations.add(System.getProperty("user.home") + "/.crypt-fetch/" + filename);
        fileLocations.add("/etc/crypt-fetch/" + filename);

        fileLocations.forEach(v -> logger.info(String.format("buildPossibleFileLocations: %s", v)));
        return fileLocations;
    }


    public static File findConfigFile(String filename) {
        final List<String> fileLocations = Utils.buildPossibleFileLocations(filename);

        File[] result = new File[1];
        fileLocations.forEach(v -> {
            File test = new File(v);
            if (test.exists()) {
                result[0] = test;
            }
        });
        if (result[0] != null) {
            return result[0];
        }

        return null;
    }


}
