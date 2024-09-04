package com.jsp.jpa.vo.user;

import com.jsp.jpa.model.user.User;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

@RequiredArgsConstructor
public class UserDetailsImpl implements UserDetails, OAuth2User {

    @Getter
    private final User user;
    private final Map<String, Object> attributes;

    // 생성자: 일반 로그인 시 사용
    public UserDetailsImpl(User user) {
        this.user = user;
        this.attributes = null; // 일반 로그인 시 OAuth2User 관련 정보가 없으므로 null로 처리
    }




    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Collection<GrantedAuthority> authorities = new ArrayList<>();
        authorities.add(() -> user.getRole().getKey()); // key: ROLE_권한
        return authorities;
    }

    @Override
    public String getUsername() {
        return user.getUserEmail();
    }

    @Override
    public String getPassword() {
        return user.getUserPW();
    }

    // == 세부 설정 == //

    @Override
    public boolean isAccountNonExpired() { // 계정의 만료 여부
        return true;
    }

    @Override
    public boolean isAccountNonLocked() { // 계정의 잠김 여부
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() { // 비밀번호 만료 여부
        return true;
    }

    @Override
    public boolean isEnabled() { // 계정의 활성화 여부
        return true;
    }

    @Override
    public Map<String, Object> getAttributes() {
        return attributes;
    }

    @Override
    public String getName() {
        return user.getUserEmail();
    }
}

