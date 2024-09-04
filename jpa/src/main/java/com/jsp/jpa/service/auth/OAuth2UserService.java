package com.jsp.jpa.service.auth;

import com.jsp.jpa.common.Role;
import com.jsp.jpa.dto.auth.OAuth2UserInfo;
import com.jsp.jpa.exception.OAuth2ProviderMismatchException;
import com.jsp.jpa.model.user.User;
import com.jsp.jpa.repository.user.UserRepository;
import com.jsp.jpa.vo.user.UserDetailsImpl;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Slf4j
@Service
@RequiredArgsConstructor
public class OAuth2UserService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;

    @Override
    @Transactional
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);

        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        String userNameAttributeName = userRequest.getClientRegistration()
                .getProviderDetails().getUserInfoEndpoint().getUserNameAttributeName();
        log.info("service registrationId : " + registrationId);
        OAuth2UserInfo oAuth2UserInfo = OAuth2UserInfo.of(registrationId, oAuth2User.getAttributes());

        User user = findOrCreateUser(oAuth2UserInfo);

        return new UserDetailsImpl(user, oAuth2User.getAttributes());
    }

    private User findOrCreateUser(OAuth2UserInfo oAuth2UserInfo) {
        Optional<User> userOptional = userRepository.findByUserEmail(oAuth2UserInfo.getEmail());

        // 이미 존재하는 사용자가 있는 경우
        if (userOptional.isPresent()) {
            User existingUser = userOptional.get();
            // 만약 기존 사용자와 현재 OAuth2 제공자가 다르면 예외를 발생시킵니다.
            if (!existingUser.getProvider().equals(oAuth2UserInfo.getProvider())) {
                throw new OAuth2AuthenticationException(
                        new OAuth2Error("provider_mismatch"),
                        "이미 사용 중인 이메일입니다. 기존 계정으로 로그인하세요."
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
