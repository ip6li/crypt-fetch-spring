package net.felsing.cryptfetchspring;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.test.context.TestContext;
import org.springframework.test.context.TestExecutionListener;

public class CryptTestExecutionListener implements TestExecutionListener {
    private static Logger logger = LogManager.getLogger(CryptTestExecutionListener.class);

    @Override
    public void beforeTestClass(TestContext testContext) throws Exception {
        logger.info("beforeTestClass : {}", testContext.getTestClass());
    }

    @Override
    public void prepareTestInstance(TestContext testContext) throws Exception {
        logger.info("prepareTestInstance : {}", testContext.getTestClass());
    }

    @Override
    public void beforeTestMethod(TestContext testContext) throws Exception {
        logger.info("beforeTestMethod : {}", testContext.getTestMethod());
    }

    @Override
    public void beforeTestExecution(TestContext testContext) throws Exception {
        logger.info("beforeTestExecution : {}", testContext.getTestClass());
    }

    @Override
    public void afterTestExecution(TestContext testContext) throws Exception {
        logger.info("afterTestExecution : {}", testContext.getTestClass());
    }

    @Override
    public void afterTestMethod(TestContext testContext) throws Exception {
        logger.info("afterTestMethod : {}", testContext.getTestMethod());
    }

    @Override
    public void afterTestClass(TestContext testContext) throws Exception {
        logger.info("afterTestClass : {}", testContext.getTestClass());
    }

}
