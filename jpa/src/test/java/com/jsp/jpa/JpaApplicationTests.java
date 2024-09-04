package com.jsp.jpa;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@SpringBootTest
class JpaApplicationTests {

	@Test
	void contextLoads() {
		BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
		String rawPassword = "1111";
		String encodedPassword = passwordEncoder.encode(rawPassword);
		System.out.println("암호화 비밀번호 : " + encodedPassword);
	}

}
