package com.jsp.jpa.service.auth;

import com.jsp.jpa.common.JwtTokenProvider;
import com.jsp.jpa.common.Role;
import com.jsp.jpa.dto.auth.AuthDto;
import com.jsp.jpa.dto.auth.OAuth2UserInfo;
import com.jsp.jpa.exception.OAuth2ProviderMismatchException;
import com.jsp.jpa.model.user.User;
import com.jsp.jpa.repository.user.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Service
@RequiredArgsConstructor
@Slf4j
public class OAuth2AuthServiceImpl {

    private final JwtTokenProvider jwtTokenProvider;
    private final RedisService redisService;
    private final UserRepository userRepository;

    @Transactional
    public AuthDto.TokenDto handleOAuth2Login(OAuth2UserInfo oAuth2UserInfo) {
        User user = findOrCreateUser(oAuth2UserInfo);

        AuthDto.TokenDto tokenDto = jwtTokenProvider.createToken(
                user.getUserIDX(),
                user.getRole().getKey(),
                user.getUserEmail()
        );

        redisService.setValuesWithTimeout(
                "RT(" + user.getUserEmail() + "):" + tokenDto.getRefreshToken(),
                tokenDto.getRefreshToken(),
                jwtTokenProvider.getTokenExpirationTime(tokenDto.getRefreshToken())
        );

        return tokenDto;
    }

    private User findOrCreateUser(OAuth2UserInfo oAuth2UserInfo) {
        Optional<User> userOptional = userRepository.findByUserEmail(oAuth2UserInfo.getEmail());

        // 이미 존재하는 사용자가 있는 경우
        if (userOptional.isPresent()) {
            User existingUser = userOptional.get();
            // 만약 기존 사용자와 현재 OAuth2 제공자가 다르면 예외를 발생시킵니다.
            if (!existingUser.getProvider().equals(oAuth2UserInfo.getProvider())) {
                throw new OAuth2ProviderMismatchException(
                        "이미 사용 중인 이메일입니다. " + existingUser.getProvider() + " 계정으로 로그인하세요."
                );
            }
            return existingUser;
        }

        // 사용자가 존재하지 않으면 새로운 사용자를 생성합니다.
        User newUser = new User(
                oAuth2UserInfo.getEmail(),
                "password123", // 소셜 로그인 사용자의 경우 실제 비밀번호는 사용하지 않음
                oAuth2UserInfo.getProvider(), // 네이버, 카카오 등의 소셜 로그인 제공자 정보
                Role.USER // 기본적으로 USER 역할 부여
        );

        return userRepository.save(newUser);
    }
}
