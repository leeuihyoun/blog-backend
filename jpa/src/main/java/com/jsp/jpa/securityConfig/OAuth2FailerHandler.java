package com.jsp.jpa.securityConfig;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

@Component
@Slf4j
public class OAuth2FailerHandler implements AuthenticationFailureHandler {
    /**
     * Called when an authentication attempt fails.
     *
     * @param request   the request during which the authentication attempt occurred.
     * @param response  the response.
     * @param exception the exception which was thrown to reject the authentication
     *                  request.
     */
    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response
            , AuthenticationException exception) throws IOException, ServletException {
        String message = "인증에 실패했습니다.";
        int statusCode = HttpServletResponse.SC_UNAUTHORIZED;

        if (exception instanceof OAuth2AuthenticationException) {
            OAuth2Error oauth2Error = ((OAuth2AuthenticationException) exception).getError();
            if ("provider_mismatch".equals(oauth2Error.getErrorCode())) {
                message = "이미 사용 중인 이메일입니다. 기존 계정으로 로그인하세요.";
                statusCode = HttpServletResponse.SC_CONFLICT; // 409 Conflict
            }
        }



        // 유니코드 문자를 URL 인코딩
        String encodedMessage = URLEncoder.encode(message, StandardCharsets.UTF_8.toString());
        // 리디렉션할 URL 설정
        String redirectUrl = "http://localhost:3000/oauth2/redirect?error=" + encodedMessage;
        // localStorage에 저장해 놓는 코드
        String script = "<script>localStorage.setItem('errorMessage', '" + encodedMessage + "');</script>";
        response.getWriter().write(script);


        // 상태 코드 설정
        response.setStatus(statusCode);

        // 리디렉션 수행
        response.sendRedirect(redirectUrl);

        // JSON 응답을 전송할 필요가 없으므로 이 부분은 주석 처리하거나 제거합니다.
        // response.setContentType("application/json;charset=UTF-8");
        // response.getWriter().write(new ObjectMapper().writeValueAsString(new ErrorResponse("AUTHENTICATION_FAILED", message)));

    }
}
