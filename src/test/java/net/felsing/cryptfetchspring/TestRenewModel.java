package net.felsing.cryptfetchspring;

import com.fasterxml.jackson.core.JsonProcessingException;
import net.felsing.cryptfetchspring.models.RenewModel;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertNotNull;

class TestRenewModel {
    Logger logger = LoggerFactory.getLogger(TestConfigModel.class);

    @Test
    void test() throws JsonProcessingException {
        RenewModel renewModel = new RenewModel("bar");

        byte[] json = renewModel.serialize();
        logger.info(new String(json));

        RenewModel renewModel2 = RenewModel.deserialize(json);
        logger.info(renewModel2.getCertificate());
        assertNotNull(renewModel2);
    }

    @Test
    void test2() throws JsonProcessingException {
        String xxx = "{\"certificate\":\"-----BEGIN CERTIFICATE-----\\nMIIDdTCCAl2gAwIBAgIHFBQRgU06yDANBgkqhkiG9w0BAQsFADBlMSowKAYDVQQD\\nDCFIb25lc3QgQWNobWV0cyB0cnVzdHdvcnRoeSBDQSBSU0ExFjAUBgNVBAoMDUhv\\nbmVzdCBBY2htZWQxEjAQBgNVBAsMCVVzZWQgQ2FyczELMAkGA1UEBhMCREUwHhcN\\nMjEwMTMxMTAwODI5WhcNMjEwMjAxMTAwODI5WjAWMRQwEgYDVQQDDAtteVVzZXJu\\nYW1lMzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALRxMpY7pDQAhH3b\\n9SjVbXikzwwQk5cheUumATDDf+rk/mNqKiqKud2EM6UJqqZqop8y9gtOdgGtwiiu\\ntotLCBc5B43bUOCnef+5BwDpEmpCRNrmbPv5cyRGjrYCcylmiSOVFaabGCKP1e8u\\nrGqSwDXYHHtF/OtVjVzGCr/lsz8i4EYfQAcOk9iVk4BH9XajzWCpJkig1fO3nZEe\\nrZATG4PMUa74KNkQrdlKvs9ixHLFfWs2ixotD7RKx/JoJQQqGgU+sfng2voijDi3\\n5I+9plEWG8TmM5hwS46WXY4Oy6aP6ieKBNUJC2dQWkde5wVwmjhtFTtNPez1NgFW\\nI86kyrMCAwEAAaN5MHcwCQYDVR0TBAIwADAdBgNVHQ4EFgQUqlFkKarAXYzp3WFe\\n99UKoPxNJnUwHwYDVR0jBBgwFoAUVvTyj+ND1RshK10/h6jpFvzbPVgwCwYDVR0P\\nBAQDAgTwMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDBDANBgkqhkiG9w0B\\nAQsFAAOCAQEAGTzQdGYdrLfKst1lxyBTberg1/j6ZieKwIXzFnD5qTy29upVfkqo\\nMAn11rxnikkIKDxty+NiyU9iimcDrQcDivPdXFwNgRe9RSZFzodRfhp8bbP6khrU\\nNV4+JBhxpBUMMuKZwSbx7+F0hDCOU61nuGsrBQGajqorpSv7PJBp0gCtetcP4QHv\\nuNk/2JWgCnmix45k8/ePmcoonIn6WEZom7F3mcqDSSbhpDBallhRFAm1PChMP0Iv\\nMq6TuTFh1tQ2wMmv6q1d+goYL3DGgB59+L9T70S+xy9SeKNJjMRD+p7H/HIzSCIf\\nKdqtCvZM75j1PIsXIAV2JRXQY9JBpkk7Gw==\\n-----END CERTIFICATE-----\\n\"}";

        RenewModel renewModel = RenewModel.deserialize(xxx.getBytes(StandardCharsets.UTF_8));
        logger.info(renewModel.getCertificate());
        assertNotNull(renewModel);
    }
}
