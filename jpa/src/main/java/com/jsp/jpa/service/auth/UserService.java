package com.jsp.jpa.service.auth;

import com.jsp.jpa.dto.auth.AuthDto;
import com.jsp.jpa.dto.auth.UserDto;
import org.springframework.stereotype.Service;

@Service
public interface UserService {
    // 회원가입
    public void registerUser(AuthDto.SignupDto signupDto);

    /**
     * 토큰으로 유저정보 가져오기
     * @param email
     * 토큰에 이메일값을 넣기 때문에
     */
    UserDto getUserInfo(String email);

    /**
     * 이메일 중복 검사
     * @param email
     * @return
     */
    boolean checkEmailDuplication(String email);

    /**
     * 비밀번호 찾기 시 일반회원인지 탐색하기 위해
     * @param email
     * @return
     */
    public boolean checkEmailDuplicationByProvider(String email);

    /**
     * 인증번호 보내기
     * @param userEmail
     */
    boolean sendCertificationEmail(String userEmail);

    /**
     * 이메일 인증검사
     * @param  userEmail, certificationNumber
     */
    boolean verifyEmail(String userEmail, String certificationNumber);

    /**
     * 비밀번호 변경
     * @param dto
     * @return
     */
    boolean changePwd(AuthDto.ChangePwdDto dto);


}
