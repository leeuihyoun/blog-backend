package com.jsp.jpa.securityConfig;

import com.jsp.jpa.common.JwtTokenProvider;
import com.jsp.jpa.dto.auth.AuthDto;
import com.jsp.jpa.dto.auth.OAuth2UserInfo;
import com.jsp.jpa.service.auth.OAuth2AuthServiceImpl;
import com.jsp.jpa.vo.user.UserDetailsImpl;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;

@RequiredArgsConstructor
@Component
@Slf4j
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {

    private final JwtTokenProvider tokenProvider;
    private final OAuth2AuthServiceImpl authService;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        // 사용자정보
        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
        Map<String, Object> attributes = oAuth2User.getAttributes();

        /*String registrationId = (String) request.getAttribute("registrationId");*/
        //
        String registrationId = ((OAuth2AuthenticationToken) authentication).getAuthorizedClientRegistrationId();
        log.info("successHandler registrationId : " + registrationId);
        OAuth2UserInfo userInfo = OAuth2UserInfo.of(registrationId, attributes);


        AuthDto.TokenDto tokenDto = authService.handleOAuth2Login(userInfo);

        // URL에 액세스 토큰과 리프레시 토큰을 쿼리 파라미터로 추가하여 프론트엔드로 리다이렉트
        String targetUrl = "http://localhost:3000/oauth2/redirect" +
                "?accessToken=" + URLEncoder.encode(tokenDto.getAccessToken(), StandardCharsets.UTF_8.name()) +
                "&refreshToken=" + URLEncoder.encode(tokenDto.getRefreshToken(), StandardCharsets.UTF_8.name());
        // redirect로 진행해야 해서 이렇게 보내준다
        response.sendRedirect(targetUrl);
    }
}