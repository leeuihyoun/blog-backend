package com.jsp.jpa.dto.auth;

import lombok.Builder;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

import java.util.Map;

@Getter
@Builder
@Slf4j
public class OAuth2UserInfo {

    private String email;
    private String name;
    private String provider;

    public static OAuth2UserInfo of(String registrationId, Map<String, Object> attributes) {
        log.info("registrationId : " + registrationId);
        switch (registrationId) {
            case "naver":
                return ofNaver(attributes);
            case "kakao":
                return ofKakao(attributes);
            default:
                throw new IllegalArgumentException("Unsupported provider: " + registrationId);
        }
    }

    private static OAuth2UserInfo ofNaver(Map<String, Object> attributes) {
        Object responseObj = attributes.get("response");
        if (responseObj instanceof Map) {
            Map<String, Object> response = (Map<String, Object>) responseObj;
            return OAuth2UserInfo.builder()
                    .email((String) response.get("email"))
                    .provider("naver")
                    .build();
        } else {
            throw new IllegalArgumentException("Invalid Naver attributes structure");
        }
    }

    private static OAuth2UserInfo ofKakao(Map<String, Object> attributes) {
        Object kakaoAccountObj = attributes.get("kakao_account");
        if (kakaoAccountObj instanceof Map) {
            Map<String, Object> kakaoAccount = (Map<String, Object>) kakaoAccountObj;
            return OAuth2UserInfo.builder()
                    .email((String) kakaoAccount.get("email"))
                    .provider("kakao")
                    .build();
        } else {
            throw new IllegalArgumentException("Invalid Kakao attributes structure");
        }
    }
}
