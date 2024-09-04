package com.jsp.jpa.common;

import com.jsp.jpa.dto.auth.AuthDto;
import com.jsp.jpa.service.auth.RedisService;
import com.jsp.jpa.service.auth.UserDetailsServiceImpl;
import com.jsp.jpa.vo.user.UserDetailsImpl;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.security.Key;
import java.util.Date;

@Slf4j
@Component
@Transactional(readOnly = true)
//Secret Key 값을 사용하기 전 미리 초기화하기 위해
//InitializingBean 인터페이스를 상속받고 afterPropertiesSet메서드를 오버라이딩해 사용하겠다.
//TokenProvider : 토큰을 생성하고 검증하며 토큰에서 정보를 꺼내 스프링 시큐리티 Authentication 객체를 생성하는 역할을 수행
public class JwtTokenProvider implements InitializingBean {

    private final UserDetailsServiceImpl userDetailsService;
    private final RedisService redisService;

    private static final String AUTHORITIES_KEY = "role";
    private static final String IDX_KEY = "idx";
    private static final String ID_KEY = "email";
    private static final String url = "https://localhost:8082";

    private final String secretKey;
    private static Key signingKey;

    private final Long accessTokenValidityInMilliseconds;
    private final Long refreshTokenValidityInMilliseconds;

    /**
     * 생성자에서 @Value 어노테이션을 이용해 application.yml에서 미리 설정해둔 값을 가져와 사용한다.
     * application.yml에 적어둔 토큰들의 유효 기간 값의 단위가 seconds이기 때문에, 1000을 곱해 milliseconds로 변경해준다.
     * @param userDetailsService
     * @param redisService
     * @param secretKey
     * @param accessTokenValidityInMilliseconds
     * @param refreshTokenValidityInMilliseconds
     */
    public JwtTokenProvider(
            UserDetailsServiceImpl userDetailsService,
            RedisService redisService,
            @Value("${jwt.secret}") String secretKey,
            @Value("${jwt.access-token-validity-in-seconds}") Long accessTokenValidityInMilliseconds,
            @Value("${jwt.refresh-token-validity-in-seconds}") Long refreshTokenValidityInMilliseconds) {
        this.userDetailsService = userDetailsService;
        this.redisService = redisService;
        this.secretKey = secretKey;
        // seconds -> milliseconds
        this.accessTokenValidityInMilliseconds = accessTokenValidityInMilliseconds * 1000;
        this.refreshTokenValidityInMilliseconds = refreshTokenValidityInMilliseconds * 1000;
    }

    /**
     *  시크릿 키 설정
     */
    @Override
    public void afterPropertiesSet() throws Exception {
        byte[] secretKeyBytes = Decoders.BASE64.decode(secretKey);
        signingKey = Keys.hmacShaKeyFor(secretKeyBytes);
    }

    @Transactional
    /**
     * 토큰 발급
     * @param email, authorities
     */
    public AuthDto.TokenDto createToken(int idx, String authorities, String email){
        Long now = System.currentTimeMillis();

        String accessToken = Jwts.builder()
                .setHeaderParam("typ", "JWT")
                .setHeaderParam("alg", "HS512")
                .setExpiration(new Date(now + accessTokenValidityInMilliseconds))
                .setSubject("access-token")
                .claim(url, true)
                .claim(IDX_KEY, idx)
                .claim(ID_KEY,email)
                .claim(AUTHORITIES_KEY, authorities)
                .signWith(signingKey, SignatureAlgorithm.HS512)
                .compact();

        String refreshToken = Jwts.builder()
                .setHeaderParam("typ", "JWT")
                .setHeaderParam("alg", "HS512")
                .setExpiration(new Date(now + refreshTokenValidityInMilliseconds))
                .setSubject("refresh-token")
                .signWith(signingKey, SignatureAlgorithm.HS512)
                .compact();

        return new AuthDto.TokenDto(accessToken, refreshToken);
    }


    // == 토큰으로부터 정보 추출 == //

    /**
     * 토큰으로부터 Claims를 추출해 반환한다.
     * @param token
     * @return Claims
     */
    public Claims getClaims(String token) {
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(signingKey)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        } catch (ExpiredJwtException e) { // Access Token
            return e.getClaims();
        }
    }

    /**
     * 토큰으로부터 인증 정보 객체인 UsernamePasswordAuthenticationToken을 반환한다.
     * @param token
     * @return Authentication
     */
    public Authentication getAuthentication(String token) {
        int idx = (int) getClaims(token).get(IDX_KEY);
        String email = getClaims(token).get(ID_KEY).toString();
        UserDetailsImpl userDetailsImpl = userDetailsService.loadUserByUsername(email);
        log.info("Extracted claims from token: {}", idx);
        log.info("Extracted authorities: {}", userDetailsImpl);
        return new UsernamePasswordAuthenticationToken(userDetailsImpl, "", userDetailsImpl.getAuthorities());
    }

    /**
     * 토큰으로부터 유효기간을 반환한다.
     * @param token
     * @return
     */
    public long getTokenExpirationTime(String token) {
        return getClaims(token).getExpiration().getTime();
    }


    // == 토큰 검증 == //
    /**
     * 토큰을 검증한다. 각 예외별로 log를 남기고 false를 반환한다.
     */
    public boolean validateRefreshToken(String refreshToken){
        log.info("레디스 : " + redisService.getValues(refreshToken));
        try {

            if (redisService.getValues(refreshToken).equals("delete")) { // 회원 탈퇴했을 경우
                return false;
            }
            Jwts.parserBuilder()
                    .setSigningKey(signingKey)
                    .build()
                    .parseClaimsJws(refreshToken);
            return true;
        } catch (SignatureException e) {
            log.error("Invalid JWT signature.");
        } catch (MalformedJwtException e) {
            log.error("Invalid JWT token.");
        } catch (ExpiredJwtException e) {
            log.error("Expired JWT token.");
        } catch (UnsupportedJwtException e) {
            log.error("Unsupported JWT token.");
        } catch (IllegalArgumentException e) {
            log.error("JWT claims string is empty.");
        } catch (NullPointerException e){
            log.error("JWT Token is empty.");
        }
        return false;
    }

    // Filter에서 사용
    /**
     * Filter에서 AT 검증을 위해 쓰인다. 기간이 만료됐을 경우에도 true를 반환한다.
     * @param accessToken
     * @return
     */
    public boolean validateAccessToken(String accessToken) {
        try {
            if (redisService.getValues(accessToken) != null // NPE 방지
                    && redisService.getValues(accessToken).equals("logout")) { // 로그아웃 했을 경우
                return false;
            }
            Jwts.parserBuilder()
                    .setSigningKey(signingKey)
                    .build()
                    .parseClaimsJws(accessToken);
            return true;
        } catch(ExpiredJwtException e) {
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    // 재발급 검증 API에서 사용

    /**
     * 유효기간만 만료된 유효한 토큰일 경우 true를 반환한다.
     * @param accessToken
     * @return
     */
    public boolean validateAccessTokenOnlyExpired(String accessToken) {
        try {
            return getClaims(accessToken)
                    .getExpiration()
                    .before(new Date());
        } catch(ExpiredJwtException e) {
            return true;
        } catch (Exception e) {
            return false;
        }
    }
/*    // 토큰에서 유저이메일 추출
    public String getUserIdFromToken(String token) {
        Claims claims = getClaims(token);
        return claims.get(EMAIL_KEY).toString();
    }*/

}


/**
 * Secret Key 값을 사용하기 전 미리 초기화하기 위해 InitializingBean 인터페이스를 상속받고 afterPropertiesSet메서드를 오버라이딩해 사용하겠다.
 * 생성자에서 @Value 어노테이션을 이용해 application.yml에서 미리 설정해둔 값을 가져와 사용한다. application.yml에 적어둔 토큰들의 유효 기간 값의 단위가 seconds이기 때문에, 1000을 곱해 milliseconds로 변경해준다.
 * createToken(String email, String authorities): 토큰 발급 메서드. User.email(Principal)값과 User.role 값을 매개변수로 받아 사용한다. 이전에 포스팅했던 claims의 종류들을 골고루 사용해보았다.
 * Refresh Token에는 claims를 최소화했다. Access Token이든
 * Refresh Token이든 탈취되어 악용되었을 때 문제가 된다. 두 토큰이 같은 정보량을 가질 때,
 * 비교적 짧은 시간 안에 유효기간이 만료되는 Access Token보다는 긴 유효기간을 가지는 Refresh Token이 탈취되었을 때
 * 더 치명적이라는 생각이 들었다. 그리고, 사용자를 "인증"하는 용도로 사용되는 Access Token과 달리,
 * Refresh Token은 Access Token의 "재발급"만을 위해 사용되기 때문에 claims를 최소화하는게 맞다고 생각했다.
 */