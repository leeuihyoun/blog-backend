package com.jsp.jpa.service.auth;

import com.jsp.jpa.common.CertificationGenerator;
import com.jsp.jpa.dto.auth.AuthDto;
import com.jsp.jpa.dto.auth.UserDto;
import com.jsp.jpa.model.user.User;
import com.jsp.jpa.repository.user.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional(readOnly = true)
public class UserServiceImpl implements UserService{

    private final UserRepository userRepository;
    private final RedisService redisService;
    private final CertificationGenerator certificationGenerator;
    private final JavaMailSender mailSender;

    @Transactional
    @Override
    /**
     * 회원가입
     */
    public void registerUser(AuthDto.SignupDto signupDto) {
        User user = User.registerUser(signupDto);
        userRepository.save(user);
    }

    @Override
    public UserDto getUserInfo(String email) {
        User user = userRepository.findByUserEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with email: " + email));

        return new UserDto(user.getUserIDX(), user.getRole(), user.getUserEmail());
    }

    /**
     * 이메일 중복 검사
     *
     * @param email
     * @return
     */
    @Override
    public boolean checkEmailDuplication(String email) {
        Optional<User> user = userRepository.findByUserEmail(email);
        log.info("user : " + user);
        return user.isPresent();
    }
    /**
     * 이메일 중복 검사
     * 비밀번호 찾기시 일반회원인지 확인하기 위해
     * @param email
     * @return
     */
    @Override
    public boolean checkEmailDuplicationByProvider(String email) {
        Optional<User> user = userRepository.findByUserEmailAndProvider(email,"일반");
        log.info("user : " + user);
        return user.isPresent();
    }

    /**
     * 인증번호 보내기
     * @param userEmail
     */
    @Override
    public boolean sendCertificationEmail(String userEmail) {
        try {
            String certificationNumber = certificationGenerator.createCertificationNumber();
            sendEmail(userEmail, certificationNumber);

            // Redis에 인증 번호 저장 (5분 후 만료)
            redisService.setValuesWithTimeout(
                    "certification:" + userEmail,
                    certificationNumber,
                    300000
            );

            return true;
        } catch (Exception e) {
            log.error("Failed to send certification email", e);
            return false;
        }
    }


    /**
     * 인증번호 확인
     * @paran userEmail, 입력한 인증번호
     */
    @Override
    public boolean verifyEmail(String userEmail, String certificationNumber) {
        String key = "certification:" + userEmail;
        String storedCertificationNumber = redisService.getValues(key);
        log.info("storedCertificationNumber: {}", storedCertificationNumber);

        if (storedCertificationNumber != null && storedCertificationNumber.equals(certificationNumber)) {
            // 인증 번호 일치 시 Redis에서 인증 번호 삭제
            redisService.deleteValues(key);
            return true;
        }
        return false;
    }

    /**
     * 비밀번호 변경
     * @param dto
     * @return
     */
    @Override
    public boolean changePwd(AuthDto.ChangePwdDto dto) {
        User user = userRepository.findByUserEmailAndProvider(dto.getEmail(),"일반")
                .orElseThrow(() -> new UsernameNotFoundException("User not found with email: " + dto.getEmail()));

        user.changePassword(dto.getPwd());
        userRepository.save(user);
        return true;
    }



    // 이메일 보내는 함수
    private void sendEmail(String userEmail, String certificationNumber) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(userEmail);
        message.setSubject("회원가입 인증 메일");
        message.setText("인증번호 : " + certificationNumber);
        mailSender.send(message);
    }


}
