package com.jsp.jpa.service.auth;

import com.jsp.jpa.dto.auth.AuthDto;
import com.jsp.jpa.dto.auth.UserDto;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public interface AuthService {

    /**
     * 로그인: 인증 정보 저장 및 비어 토큰 발급
     * @param loginDto
     * @return
     */
    @Transactional
    public AuthDto.TokenDto login(AuthDto.LoginDto loginDto);

    /**
     * AT가 만료일자만 초과한 유효한 토큰인지 검사
     * @param requestAccessTokenInHeader
     * @return
     */
    public boolean validate(String requestAccessTokenInHeader);



    /**
     * 토큰 재발급: validate 메서드가 true 반환할 때만 사용 -> AT, RT 재발급
     * @param requestAccessTokenInHeader
     * @param requestRefreshToken
     * @return
     */
    public AuthDto.TokenDto reissue(String requestAccessTokenInHeader, String requestRefreshToken);


    /**
     * 토큰 발급
     * Redis에 기존의 RT가 이미 있을 경우, 삭제한다. AT와 RT를 생성하고, Redis에 새로 발급한 RT를 저장한다.
     * @param provider
     * @param email
     * @param authorities
     * @return
     */
    public AuthDto.TokenDto generateToken(int idx, String provider, String email, String authorities);

    /**
     * RT를 Redis에 저장
     * @param provider
     * @param principal
     * @param refreshToken
     */
    @Transactional
    public void saveRefreshToken(String provider, String principal, String refreshToken);

    /**
     * 역할 가져오기
     * @param authentication
     * @return
     */
    public String getAuthorities(Authentication authentication);

    /**
     * AT로부터 principal 추출
     * @param requestAccessToken
     * @return
     */
    public String getPrincipal(String requestAccessToken);

    /**
     * "Bearer {AT}"에서 {AT} 추출
     * @param requestAccessTokenInHeader
     * @return
     */
    public String resolveToken(String requestAccessTokenInHeader);

    /**
     * 로그아웃
     * Redis에 저장되어 있는 RT를 삭제하고, Redis에 로그아웃 처리한 AT 저장해 해당 AT를 이용한 요청을 방지한다.
     * @param requestAccessTokenInHeader
     */
    @Transactional
    public void logout(String requestAccessTokenInHeader);

    //

    /**
     * 유저정보 조회
     * @param token
     */
    @Transactional
    UserDto getUserInfo(String token);

    boolean isValidUser(String token, int idx);

    /**
     * 회원 탈퇴
     * @param requestAccessToken
     */
    void signOut(String requestAccessToken);
}
