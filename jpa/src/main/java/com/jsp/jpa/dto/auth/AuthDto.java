package com.jsp.jpa.dto.auth;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * 인증과정에서 필요한 DTO
 */
public class AuthDto {

    @Getter
    @NoArgsConstructor(access = AccessLevel.PROTECTED)
    public static class LoginDto {
        private String email;
        private String password;

        @Builder
        /**
         * 로그인할 때 필요하다
         */
        public LoginDto(String email, String password) {
            this.email = email;
            this.password = password;
        }
    }

    /**
     * 회원가입할 때 필요하다
     */
    @Getter
    @NoArgsConstructor(access = AccessLevel.PROTECTED)
    public static class SignupDto {
        @NotBlank(message = "이메일은 필수 입력 항목입니다.")
        @Email(message = "유효한 이메일 주소여야 합니다.")
        @Pattern(regexp = "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$", message = "유효한 이메일 주소여야 합니다.")
        private String email;

        @NotBlank(message = "비밀번호는 필수 입력 항목입니다.")
        @Pattern(regexp = "^(?=.*[A-Za-z])(?=.*\\d)[A-Za-z\\d]{8,20}$", message = "비밀번호는 영문자와 숫자를 포함하여 8~20자이어야 합니다.")
        private String password;

        private String provider;

        @Builder
        public SignupDto(String email, String password, String provider) {
            this.email = email;
            this.password = password;
            this.provider = provider != null ? provider : "일반";
        }

        public static SignupDto encodePassword(SignupDto signupDto, String encodedPassword) {
            SignupDto newSignupDto = new SignupDto();
            newSignupDto.email = signupDto.getEmail();
            newSignupDto.password = encodedPassword;
            return newSignupDto;
        }
    }

    @Getter
    @NoArgsConstructor(access = AccessLevel.PROTECTED)
    public static class TokenDto {
        private String accessToken;
        private String refreshToken;

        public TokenDto(String accessToken, String refreshToken) {
            this.accessToken = accessToken;
            this.refreshToken = refreshToken;
        }
    }

    @Getter
    @NoArgsConstructor(access = AccessLevel.PROTECTED)
    public static class ChangePwdDto{
        private String email;
        private String pwd;
        private String pwdCheck;

        @Builder
        public ChangePwdDto(String email, String pwd, String pwdCheck){
            this.email = email;
            this.pwd = pwd;
            this.pwdCheck = pwdCheck;
        }

        public static ChangePwdDto encodePassword(ChangePwdDto changePwdDto, String encodedPassword) {
            ChangePwdDto newChangePwdDto = new ChangePwdDto();
            newChangePwdDto.email = changePwdDto.getEmail();
            newChangePwdDto.pwd = encodedPassword;
            return newChangePwdDto;
        }
    }
}