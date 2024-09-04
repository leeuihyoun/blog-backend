package com.jsp.jpa.dto.auth;

import com.jsp.jpa.common.Role;
import lombok.Data;

@Data
public class UserDto {
    private int idx;
    private String email;
    private Role role;

    public UserDto(int idx, Role role, String email) {
        this.idx = idx;
        this.role = role;
        this.email = email;
    }

    // getters and setters
}