package com.jsp.jpa.dto.mail;

import lombok.Data;

@Data
public class VerifyEmailRequest {
    private String userEmail;
    private String certificationNumber;
}
