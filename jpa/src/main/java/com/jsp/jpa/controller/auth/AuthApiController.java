package com.jsp.jpa.controller.auth;

import com.jsp.jpa.dto.auth.AuthDto;
import com.jsp.jpa.dto.auth.UserDto;
import com.jsp.jpa.dto.mail.SendCertificationEmailRequest;
import com.jsp.jpa.dto.mail.VerifyEmailRequest;
import com.jsp.jpa.repository.user.UserRepository;
import com.jsp.jpa.service.auth.AuthServiceImpl;
import com.jsp.jpa.service.auth.UserServiceImpl;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.*;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthApiController {

    private final AuthServiceImpl authService;
    private final UserServiceImpl userService;
    private final BCryptPasswordEncoder encoder;

    private final long COOKIE_EXPIRATION = 7776000; // 90일

    /**
     * 회원을 등록한다. 중복 이메일에 대한 검사가 추가적으로 필요하지만, 우선 단순하게 진행하겠다.
     * 원래는 UserService에서 암호화하려고 했지만, 순환 참조 문제로 BCryptPasswordEncoder를 Controller단으로 가져왔다.
     * @param signupDto
     * @return
     */
    @PostMapping("/signup")
    public ResponseEntity<?> signup(@RequestBody @Valid AuthDto.SignupDto signupDto, BindingResult result) {
        String encodedPassword = encoder.encode(signupDto.getPassword());
        AuthDto.SignupDto newSignupDto = AuthDto.SignupDto.encodePassword(signupDto, encodedPassword);

        if (result.hasErrors()) {
            return ResponseEntity.badRequest().body(result.getAllErrors());
        }

        userService.registerUser(newSignupDto);
        return new ResponseEntity<>(HttpStatus.OK);
    }

    /**
     * 로그인 -> 토큰 발급
     * authService.login 메서드를 실행하고 토큰을 발급받는다.
     * RT를 HTTP-ONLY Secure Cookie로, AT를 Authorization Header에 담아 보낸다.
     * @param loginDto
     * @return
     */
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody @Valid AuthDto.LoginDto loginDto) {
        // User 등록 및 Refresh Token 저장
        if(loginDto.getEmail().isEmpty() || loginDto.getPassword().isEmpty()){
            return ResponseEntity.badRequest().body("empty");
        }

        AuthDto.TokenDto tokenDto = authService.login(loginDto);

        // RT 저장
        HttpCookie httpCookie = ResponseCookie.from("refresh-token", tokenDto.getRefreshToken())
                .maxAge(COOKIE_EXPIRATION)
                .httpOnly(true)
                .path("/") // 쿠키가 모든 경로에서 유효하도록 설정
                .secure(true)
                .build();
        log.info("AccessToken : " + tokenDto.getAccessToken());
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, httpCookie.toString())
                // AT 저장
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + tokenDto.getAccessToken())
                .build();
    }

    /**
     * AT를 재발급받을 필요가 없다면 상태 코드 OK(200)을 반환하고, 재발급받아야 한다면 401을 반환
     * @param requestAccessToken
     * @return
     */
    @PostMapping("/validate")
    public ResponseEntity<?> validate(@RequestHeader("Authorization") String requestAccessToken) {

        if (!authService.validate(requestAccessToken)) {
            String token = requestAccessToken.replace("Bearer ", "").trim();
            return ResponseEntity.status(HttpStatus.OK).body("success"); // 재발급 필요X
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build(); // 재발급 필요
        }
    }

    /**
     * 토큰 재발급
     * validate 요청으로부터 UNAUTHORIZED(401)을 반환받았다면,
     * 프론트에서 Cookie와 Header에 각각 RT와 AT를 요청으로 받아서
     * authService.reissue를 통해 토큰 재발급을 진행한다.
     * 토큰 재발급이 성공한다면 login과 마찬가지로 응답 결과를 보내고,
     * 토큰 재발급이 실패했을때(null을 반환받았을 때) Cookie에 담긴 RT를 삭제하고 재로그인을 유도한다.
     * @param requestRefreshToken
     * @param requestAccessToken
     * @return
     */
    @PostMapping("/reissue")
    public ResponseEntity<?> reissue(@CookieValue(name = "refresh-token") String requestRefreshToken,
                                     @RequestHeader("Authorization") String requestAccessToken) {
        AuthDto.TokenDto reissuedTokenDto = authService.reissue(requestAccessToken, requestRefreshToken);

        if (reissuedTokenDto != null) { // 토큰 재발급 성공
            // RT 저장
            ResponseCookie responseCookie = ResponseCookie.from("refresh-token", reissuedTokenDto.getRefreshToken())
                    .maxAge(COOKIE_EXPIRATION)
                    .httpOnly(true)
                    .secure(true)
                    .build();

            String token = reissuedTokenDto.getAccessToken().replace("Bearer ", "").trim();
            UserDto userInfo = authService.getUserInfo(token);
            return ResponseEntity
                    .status(HttpStatus.OK)
                    .header(HttpHeaders.SET_COOKIE, responseCookie.toString())
                    // AT 저장
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + reissuedTokenDto.getAccessToken())
                    .build();

        } else { // Refresh Token 탈취 가능성
            // Cookie 삭제 후 재로그인 유도
            ResponseCookie responseCookie = ResponseCookie.from("refresh-token", "")
                    .maxAge(0)
                    .path("/")
                    .build();
            return ResponseEntity
                    .status(HttpStatus.UNAUTHORIZED)
                    .header(HttpHeaders.SET_COOKIE, responseCookie.toString())
                    .build();
        }
    }

    /**
     * 로그아웃
     * authService.logout을 진행한 후, Cookie에 담긴 RT를 삭제한다.
     * @param requestAccessToken
     * @return
     */
    @PostMapping("/logout")
    public ResponseEntity<?> logout(@RequestHeader("Authorization") String requestAccessToken) {
        String token = requestAccessToken.replace("Bearer", "").trim(); // Bearer 제거 및 공백 제거
        log.info("token : " + token);
        log.info("requestAccessToken : " + requestAccessToken);
        authService.logout(requestAccessToken);

        ResponseCookie responseCookie = ResponseCookie.from("refresh-token", "")
                .maxAge(0)
                .path("/")
                .build();

        return ResponseEntity
                .status(HttpStatus.OK)
                .header(HttpHeaders.SET_COOKIE, responseCookie.toString())
                .build();
    }
    /**

    /**
     * 사용자 정보 조회
     * @param requestAccessToken
     * @return 사용자 정보
     */
    @GetMapping("/userinfo")
    public ResponseEntity<?> getUserInfo(@RequestHeader("Authorization") String requestAccessToken) {
        String token = requestAccessToken.replace("Bearer ", "").trim();
        UserDto userInfo = authService.getUserInfo(token);
        System.out.print(userInfo);
        log.info("userInfo : " + userInfo);
        if (!authService.isValidUser(token, userInfo.getIdx())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        return ResponseEntity.ok(userInfo);
    }

    /**
     * 중복 검사
     * @param request
     * @return
     */
    @PostMapping("/check-email")
    public ResponseEntity<?> checkEmail( @RequestBody @Valid Map<String, String> request, BindingResult result){
        String email = request.get("email");
        String type = request.get("type");
        log.info("type : " + type);
        if (result.hasErrors()) {
            return ResponseEntity.badRequest().body(result.getAllErrors());
        }

        log.info("email : " + email);

        boolean isDuplicate = userService.checkEmailDuplication(email);
        log.info("isDuplicate : " + isDuplicate);
        if (isDuplicate) {
            return ResponseEntity.status(409).body("이메일이 이미 사용 중입니다.");
        } else {
            return ResponseEntity.ok("사용 가능한 이메일입니다.");
        }
    }

    /**
     * 인증 버튼 눌렀을 시 인증코드를 받기 위해 접근
     * @param request
     * @return
     */
    @PostMapping("/verify-email")
    public ResponseEntity<?> sendVerifyCode(@RequestBody SendCertificationEmailRequest request){
        String email = request.getUserEmail();
        log.info("type : " + request.getType());
        
        if (email == null || email.trim().isEmpty()) {
            return ResponseEntity.badRequest().body("Invalid email address");
        }

        email = email.trim();
        log.info("email : " + email);
        boolean sendResult = userService.sendCertificationEmail(email);

        if (sendResult) {
            return ResponseEntity.ok("success");
        } else {
            return ResponseEntity.internalServerError().body("fail");
        }
    }

    @PostMapping("/verify-number")
    public ResponseEntity<?> matchVerifyNumber(@RequestBody VerifyEmailRequest request){

        log.info("들어온 값" + request);

        // 서비스를 통해 이메일 인증 번호를 검증하고 결과를 반환
        boolean verificationResult = userService.verifyEmail(request.getUserEmail(), request.getCertificationNumber());

        if (verificationResult) {
            return ResponseEntity.ok("success");
        } else {
            return ResponseEntity.status(400).body("fail");
        }

    }

    /**
     * 비밀번호 변경
     * @param dto
     * @return
     */
    @PatchMapping("/change-pwd")
    public ResponseEntity<?> changePwd(@RequestBody AuthDto.ChangePwdDto dto){
        log.info("dto : " + dto);
        log.info("pwd : " + dto.getPwd());
        if(!dto.getPwd().equals(dto.getPwdCheck())){
            return ResponseEntity.badRequest().body("fail");
        }
        userService.changePwd(AuthDto.ChangePwdDto.encodePassword(dto, encoder.encode(dto.getPwd())));
        return ResponseEntity.ok("success");
    }

    @DeleteMapping("/sign-out")
    public ResponseEntity<?> signOut(@RequestHeader("Authorization") String requestAccessToken){
        authService.signOut(requestAccessToken);

        ResponseCookie responseCookie = ResponseCookie.from("refresh-token", "")
                .maxAge(0)
                .path("/")
                .build();

        return ResponseEntity
                .status(HttpStatus.OK)
                .header(HttpHeaders.SET_COOKIE, responseCookie.toString())
                .build();
    }

}
