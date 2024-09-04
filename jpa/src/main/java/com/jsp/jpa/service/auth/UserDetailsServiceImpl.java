package com.jsp.jpa.service.auth;

import com.jsp.jpa.model.user.User;
import com.jsp.jpa.repository.user.UserRepository;
import com.jsp.jpa.vo.user.UserDetailsImpl;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
@Slf4j
public class UserDetailsServiceImpl implements UserDetailsService {

    private final UserRepository userRepository;


    @Override
    public UserDetailsImpl loadUserByUsername(String email) throws UsernameNotFoundException {
        log.info("아이디 : " + email);
        User findUser = userRepository.findByUserEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("Can't find user with this email. -> " + email));

        if(findUser != null){
            UserDetailsImpl userDetails = new UserDetailsImpl(findUser);
            return  userDetails;
        }

        return null;
    }
}
