package com.jsp.jpa.securityConfig;

import com.jsp.jpa.common.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.annotation.web.configurers.FormLoginConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.annotation.web.configurers.HttpBasicConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtTokenProvider jwtTokenProvider;
    private final JwtAccessDeniedHandler jwtAccessDeniedHandler;
    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;

    @Bean
    public BCryptPasswordEncoder encoder() {
        // 비밀번호를 DB에 저장하기 전 사용할 암호화
        return new BCryptPasswordEncoder();
    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        // ACL(Access Control List, 접근 제어 목록)의 예외 URL 설정
        return (web)
                -> web
                .ignoring()
                .requestMatchers(PathRequest.toStaticResources().atCommonLocations()); // 정적 리소스들
    }

    @Bean
    public SecurityFilterChain FilterChain(HttpSecurity http) throws Exception {
        // 인터셉터로 요청을 안전하게 보호하는 방법 설정
        http
                // jwt 토큰 사용을 위한 설정
                .csrf(CsrfConfigurer::disable) // JWT를 사용하기 떄문에 csrf토큰 없어도 됨
                .httpBasic(HttpBasicConfigurer::disable)// JWT를 사용하기 때문에 꺼둠
                .formLogin(FormLoginConfigurer::disable)// JWT를 사용하기 때문에 꺼둠
                .addFilterBefore(new JwtAuthenticationFilter(jwtTokenProvider), UsernamePasswordAuthenticationFilter.class)
                .sessionManagement(sessionManagement ->
                    sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                ) // JWT를 사용하기 때문에 세션을 꺼둠

                // 예외 처리
                .exceptionHandling(exceptionHandling -> exceptionHandling
                        .authenticationEntryPoint(jwtAuthenticationEntryPoint) // 인가에 실패했을 때
                        .accessDeniedHandler(jwtAccessDeniedHandler)// 인증에 실패했을 때
                )

                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/api/auth/**").permitAll()
                        .requestMatchers("/api/auth/my-reviews").authenticated()
                        .requestMatchers("/api/auth//reviews/**").authenticated()
                        .requestMatchers("/api/mypage/**").hasAnyRole("USER", "ADMIN")
                        .anyRequest().authenticated()

                        /*.requestMatchers("/api/admin/**").hasRole("ADMIN")
                        .anyRequest().authenticated()*/
                )
                .headers(headers -> headers
                        .frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin)
                );

        return http.build();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }



}
/**
 * SecurityConfig.class에서 UsernamePasswordAuthenticationFilter 이전에 통과할 Filter이다.
 * 인증(Authentication)이 필요한 요청(Request)이 오면 요청의 헤더(Header)에서 Access Token을 추출하고 정상 토큰인지 검사한다.
 * jwtTokenProvider.validateToken(accessToken) 메서드를 통해 유효 기간을 제외하고 정상적인 Access Token인지 검사한다.
 * 유효 기간만 제외하고 정상적인 토큰일 경우, 유저 모르게 Access Token을 재발급하고 로그인을 연장시킴과 동시에 다시 요청을 처리하도록 하기 위함이다.(Silent refresh) 이 작업을 진행하기 위해서는 프론트엔드에서 추가 작업이 필요하다. 재발급 API에 접근한 후, 응답에 따라 원래 처리할 요청 or 로그인으로 리다이렉트되게끔 해야 한다.
 * logout 처리된 Access Token은 더이상 사용하지 못하게 하기 위해 Redis에 저장할 예정이기 때문에
 * Redis에 logout 여부를 확인하는 로직을 추가했다.
 */
