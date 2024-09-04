package com.jsp.jpa.model.user;

import com.jsp.jpa.common.Role;
import com.jsp.jpa.dto.auth.AuthDto;
import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.ColumnDefault;

@Entity(name = "member")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "member_idx")
    private int userIDX;

    @Column(name = "member_email", unique = true, nullable = false)
    private String userEmail; // Principal

    @Column(name = "member_pwd", nullable = false)
    private String userPW; // Credential

    @Column(name = "member_provider")
    @ColumnDefault("일반")
    private String provider;

    @Enumerated(EnumType.STRING)
    @Column(name = "member_role")
    private Role role; // 사용자 권한


    // == 생성 메서드 == //
    public static User registerUser(AuthDto.SignupDto signupDto) {
        User user = new User();

        user.userEmail = signupDto.getEmail();
        user.userPW = signupDto.getPassword();
        user.provider = signupDto.getProvider() != null ? signupDto.getProvider() : "일반";
        user.role = Role.USER;
        return user;
    }

    @Builder
    public User(String email, String pwd, String provider, Role role){
        this.userEmail = email;
        this.userPW = pwd;
        this.provider = provider;
        this.role = role;
    }

    public void changePassword(String encodedPassword) {
        this.userPW = encodedPassword;
    }


}