package com.jsp.jpa.common;

import org.springframework.stereotype.Component;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

@Component
public class CertificationGenerator {
    public String createCertificationNumber() throws NoSuchAlgorithmException {
        String result;

        do {
            int num = SecureRandom.getInstanceStrong().nextInt(999999);
            result = String.format("%06d", num); // 6자리 숫자로 포맷팅
        } while (result.length() != 6);

        return result;
    }
}
