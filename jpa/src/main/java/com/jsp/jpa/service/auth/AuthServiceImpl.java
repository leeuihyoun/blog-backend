package com.jsp.jpa.service.auth;

import com.jsp.jpa.common.JwtTokenProvider;
import com.jsp.jpa.dto.auth.AuthDto;
import com.jsp.jpa.dto.auth.UserDto;
import com.jsp.jpa.model.user.User;
import com.jsp.jpa.repository.user.UserRepository;
import com.jsp.jpa.vo.user.UserDetailsImpl;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Date;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthServiceImpl implements AuthService{

    private final JwtTokenProvider jwtTokenProvider;
    private final AuthenticationManagerBuilder authenticationManagerBuilder;
    private final RedisService redisService;
    private final UserRepository userRepository;

    private final String SERVER = "Server";
    /**
     * 로그인: 인증 정보 저장 및 비어 토큰 발급
     *
     * @param loginDto
     * @return
     */
    @Transactional
    @Override
    public AuthDto.TokenDto login(AuthDto.LoginDto loginDto) {
        // 유저 아이디와 비밀번호를 가져와서 인증토큰을 만든다
        log.info("로그인 서비스");
        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(loginDto.getEmail(), loginDto.getPassword());
        log.info("로그인 정보 : " + loginDto.getEmail());

        Authentication authentication = authenticationManagerBuilder.getObject()
                .authenticate(authenticationToken);

        User user = userRepository.findByUserEmailAndProvider(loginDto.getEmail(),"일반")
                .orElseThrow(() -> new UsernameNotFoundException("User not found with email: " + loginDto.getEmail()));

        SecurityContextHolder.getContext().setAuthentication(authentication);
        return generateToken(user.getUserIDX(), SERVER, user.getUserEmail(), getAuthorities(authentication));
    }

    /**
     * AT가 만료일자만 초과한 유효한 토큰인지 검사
     *
     * @param requestAccessTokenInHeader
     * @return
     */
    @Override
    public boolean validate(String requestAccessTokenInHeader) {
        String requestAccessToken = resolveToken(requestAccessTokenInHeader);
        return jwtTokenProvider.validateAccessTokenOnlyExpired(requestAccessToken); // true = 재발급
    }

    /**
     * 토큰 재발급: validate 메서드가 true 반환할 때만 사용 -> AT, RT 재발급
     *
     * @param requestAccessTokenInHeader
     * @param requestRefreshToken
     * @return
     */
    @Transactional
    @Override
    public AuthDto.TokenDto reissue(String requestAccessTokenInHeader, String requestRefreshToken) {
        String requestAccessToken = resolveToken(requestAccessTokenInHeader);

        Authentication authentication = jwtTokenProvider.getAuthentication(requestAccessToken);
        String principal = getPrincipal(requestAccessToken);

        String refreshTokenInRedis = redisService.getValues("RT(" + SERVER + "):" + principal);
        if (refreshTokenInRedis == null) { // Redis에 저장되어 있는 RT가 없을 경우
            return null; // -> 재로그인 요청
        }

        // 요청된 RT의 유효성 검사 & Redis에 저장되어 있는 RT와 같은지 비교
        if(!jwtTokenProvider.validateRefreshToken(requestRefreshToken) || !refreshTokenInRedis.equals(requestRefreshToken)) {
            redisService.deleteValues("RT(" + SERVER + "):" + principal); // 탈취 가능성 -> 삭제
            return null; // -> 재로그인 요청
        }

        SecurityContextHolder.getContext().setAuthentication(authentication);
        String authorities = getAuthorities(authentication);
        int idx = getIdx(authentication);
        String id = getId(authentication);

        // 토큰 재발급 및 Redis 업데이트
        redisService.deleteValues("RT(" + SERVER + "):" + principal); // 기존 RT 삭제
        AuthDto.TokenDto tokenDto = jwtTokenProvider.createToken(idx, authorities, id);
        saveRefreshToken(SERVER, principal, tokenDto.getRefreshToken());
        return tokenDto;
    }

    /**
     * 토큰 발급
     * Redis에 기존의 RT가 이미 있을 경우, 삭제한다. AT와 RT를 생성하고, Redis에 새로 발급한 RT를 저장한다.
     *
     * @param provider
     * @param email
     * @param authorities
     * @return
     */
    @Transactional
    @Override
    public AuthDto.TokenDto generateToken(int idx, String provider, String email, String authorities) {
        // RT가 이미 있을 경우
        if(redisService.getValues("RT(" + provider + "):" + email) != null) {
            redisService.deleteValues("RT(" + provider + "):" + email); // 삭제
        }

        // AT, RT 생성 및 Redis에 RT 저장
        AuthDto.TokenDto tokenDto = jwtTokenProvider.createToken(idx, authorities, email);
        saveRefreshToken(provider, email, tokenDto.getRefreshToken());
        return tokenDto;
    }

    /**
     * RT를 Redis에 저장
     *
     * @param provider
     * @param principal
     * @param refreshToken
     */
    @Transactional
    @Override
    public void saveRefreshToken(String provider, String principal, String refreshToken) {
        redisService.setValuesWithTimeout("RT(" + provider + "):" + principal, // key
                refreshToken, // value
                jwtTokenProvider.getTokenExpirationTime(refreshToken)); // timeout(milliseconds)
    }

    /**
     * 역할 가져오기
     *
     * @param authentication
     * @return
     */
    @Override
    public String getAuthorities(Authentication authentication) {
        return authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));
    }

    /**
     * AT로부터 principal 추출
     *
     * @param requestAccessToken
     * @return
     */
    @Override
    public String getPrincipal(String requestAccessToken) {
        return jwtTokenProvider.getAuthentication(requestAccessToken).getName();
    }

    /**
     * "Bearer {AT}"에서 {AT} 추출
     *
     * @param requestAccessTokenInHeader
     * @return
     */
    @Override
    public String resolveToken(String requestAccessTokenInHeader) {
        if (requestAccessTokenInHeader != null && requestAccessTokenInHeader.startsWith("Bearer ")) {
            return requestAccessTokenInHeader.substring(7);
        }
        return null;
    }

    /**
     * 로그아웃
     * Redis에 저장되어 있는 RT를 삭제하고, Redis에 로그아웃 처리한 AT 저장해 해당 AT를 이용한 요청을 방지한다.
     *
     * @param requestAccessTokenInHeader
     */
    @Override
    @Transactional
    public void logout(String requestAccessTokenInHeader) {
        String requestAccessToken = resolveToken(requestAccessTokenInHeader);
        String principal = getPrincipal(requestAccessToken);

        // Redis에 저장되어 있는 RT 삭제
        String refreshTokenInRedis = redisService.getValues("RT(" + SERVER + "):" + principal);
        if (refreshTokenInRedis != null) {
            redisService.deleteValues("RT(" + SERVER + "):" + principal);
        }

        // Redis에 로그아웃 처리한 AT 저장
        long expiration = jwtTokenProvider.getTokenExpirationTime(requestAccessToken) - new Date().getTime();
        redisService.setValuesWithTimeout(requestAccessToken,
                "logout",
                expiration);
    }
    @Transactional
    @Override
    public UserDto getUserInfo(String token) {
        Claims claims = jwtTokenProvider.getClaims(token);
        int idx = claims.get("idx", Integer.class);
        User user = userRepository.findByUserIDX(idx)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with email: " + idx));
        return new UserDto(user.getUserIDX(), user.getRole(),user.getUserEmail());
    }

    @Override
    public boolean isValidUser(String token, int idx){
        Claims claims = jwtTokenProvider.getClaims(token);
        int tokenIdx = claims.get("idx", Integer.class);
        return tokenIdx == idx;
    }



    private int getIdx(Authentication authentication) {
        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        return userDetails.getUser().getUserIDX();
    }

    private String getId(Authentication authentication) {
        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        return userDetails.getUser().getUserEmail(); // 사용자 ID를 추출합니다.
    }

    /**
     * 회원 탈퇴
     *
     * @param requestAccessToken
     */
    @Override
    @Transactional
    public void signOut(String requestAccessToken) {
        String token = resolveToken(requestAccessToken);

        String principal = getPrincipal(token);
        log.info("principal : " + principal);

        // Redis에 저장되어 있는 RT 삭제
        String refreshTokenInRedis = redisService.getValues("RT(" + SERVER + "):" + principal);
        if (refreshTokenInRedis != null) {
            redisService.deleteValues("RT(" + SERVER + "):" + principal);
        }

        User user = userRepository.findByUserEmail(principal)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with email: " + principal));
        userRepository.delete(user);
    }

}

/**
 * Refresth Token(이하 RT)과 Access Token(이하 AT)를 다루기 위해 생성한 Service단 클래스이다.
 * 코드를 이렇게 작성한 이유와 주석 외의 추가 설명이 필요하다고 생각되는 부분을 적어   보겠다.
 *
 * 큰 틀은 이렇게 된다.
 *
 * 요청 -> AT 검사 -> AT 유효 -> 요청 실행
 * 요청 -> AT 검사 -> AT 기간만 만료 -> AT, RT로 재발급 요청 -> RT 유효 -> 재발급
 * 요청 -> AT 검사 -> AT 기간만 만료 -> AT, RT로 재발급 요청 -> RT 유효X -> 재로그인
 * 변수
 * SERVER: RT를 생성한 후 Redis에 {key:RT({발급자}):{email}, value:{RT}} 형식으로 저장할 예정이다. OAuth2.0 OPEN API를 적용할 때 발급자에 Naver, Kakao 등 발급된 서버를 표시해두기 위해서이다. 자세한 내용은 나중에 OAuth2.0 OPEN API에 관련된 포스팅에서 다루겠다. 일단 우리 서버에서 발급된 RT는 {key:RT(Server):{email}, value:{RT}} 형식으로 Redis에 저장된다는 것만 기억하면 된다.
 * requestAccessTokenInHeader: "Bearer {AT}"의 형식을 갖고 있다.
 * resolveToken(String requestAccessTokenInHeader) 메서드를 통해 "Bearer {AT}"로부터 AT를 추출할 예정이다. Controller단에서 추출해 Service단으로 가져와도 크게 상관 없을 것이다. 하지만, 나중에 OAuth2.0 OPEN API에서 사용할 때 서버(Naver, Kakao 등)별로 Controller를 분리하게 될텐데 그 때의 반복되는 코드 작성을 피하고, Controller단과 Service단의 기능을 분리하기 위해서 이처럼 작성하게 되었다.
 *
 * 메서드
 * login: Filter 과정을 거치고 생성된 UsernamePasswordAuthenticationToken으로부터 Authentication 객체를 생성해 SecurityContextHolder에 저장한다. generateToken 메서드를 통해 RT와 AT를 발급해 반환한다.
 * DB에 저장된 인코딩된 값과 입력된 비밀번호를 어떻게 비교하는지
 *
 *
 *
 * login 메서드에서 사용자로부터 입력받은 email과 password 값을 이용해 UsernamePasswordAuthenticationToken을 생성하게 되고, AuthenticationManagerBuilder를 통해 사용자 인증을 진행하게 됩니다. AuthenticationManagerBuilder는 자신이 가지고 있는 인코더로 사용자로부터 입력받은 password 값, 즉 Credential을 암호화합니다.
 *
 * 이 때, AuthenticationManagerBuilder의 defaultPasswordEncorder가 사용자가 회원가입할 때 사용했던 BCryptPasswordEncoder이기 때문에 입력된 비밀번호와 DB에 저장되어 있는 값과 비교가 가능하게 됩니다.
 *
 * validate: 만료일자만 만료된 유효한 토큰인지 검사하고, 해당할 경우에 true를 리턴한다.
 *
 * reissue: 요청으로 받은 AT와 RT를 검사한 후, 토큰을 재발급하는 메서드이다. AT로부터 Authentication 객체를 가져온다. SecurityContextHolder에 객체를 저장하기 전, 다음의 두 과정을 통과해야 한다.
 *
 * Redis에 저장되어 있는 기존 Redis가 있어야 한다. 만약 없을 경우, 로그인이 만료되었다고 보고, null을 반환함으로써 재로그인을 요청한다.
 * 요청으로 받은 RT가 유효한지 검사하고, Redis에 저장된 기존 RT와 같은지 비교한다. 만약 유효하지 않거나 기존 RT와 다르다고 판단되면 RT가 탈취되었다고 결론 내리고, null을 반환함으로써 재로그인을 요청한다.
 * 두 과정을 거치고 난 후, Authentication 객체를 저장한다. 그리고, AT와 RT를 재발급하고 발급된 RT를 Redis에 저장한다.
 *
 * generateToken: Redis에 기존의 RT가 이미 있을 경우, 삭제한다. AT와 RT를 생성하고, Redis에 새로 발급한 RT를 저장한다.
 *
 * logout: Redis에 저장되어 있는 RT를 삭제하고, Redis에 로그아웃 처리한 AT 저장해 해당 AT를 이용한 요청을 방지한다.
 */
