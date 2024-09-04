package com.jsp.jpa.dto.mail;

import lombok.Data;

@Data
public class SendCertificationEmailRequest {
    private String userEmail;
    private String type;
}