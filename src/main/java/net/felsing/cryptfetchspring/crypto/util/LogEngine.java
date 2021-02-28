package net.felsing.cryptfetchspring.crypto.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class LogEngine {
    private final Logger logger;

    private LogEngine(Class<?> clazz) {
        logger = LoggerFactory.getLogger(clazz);
    }

    public static LogEngine getLogger(Class<?> clazz) {

        return new LogEngine(clazz);
    }

    public void trace(String msg) {
        if (logger.isTraceEnabled()) {
            logger.trace(msg);
        }
    }

    public void debug(String msg) {
        if (logger.isDebugEnabled()) {
            logger.debug(msg);
        }
    }

    public void info(String msg) {
        if (logger.isInfoEnabled()) {
            logger.info(msg);
        }
    }

    public void warn(String msg) {
        if (logger.isWarnEnabled()) {
            logger.warn(msg);
        }
    }

    public void error(String msg) {
        if (logger.isErrorEnabled()) {
            logger.error(msg);
        }
    }
}
