package com.jsp.jpa.repository.user;

import com.jsp.jpa.dto.auth.AuthDto;
import com.jsp.jpa.model.user.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.OptionalInt;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUserEmail(String userEmail);

    Optional<User> findByUserIDX(int idx);

    Optional<User> findByUserEmailAndProvider(String userEmail, String provider);


}