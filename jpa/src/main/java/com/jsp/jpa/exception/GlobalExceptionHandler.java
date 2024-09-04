package com.jsp.jpa.exception;

import com.jsp.jpa.dto.auth.ErrorResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(OAuth2ProviderMismatchException.class)
    public ResponseEntity<ErrorResponse> handleOAuth2ProviderMismatchException(OAuth2ProviderMismatchException ex) {
        ErrorResponse errorResponse = new ErrorResponse("EMAIL_ALREADY_IN_USE", ex.getMessage());
        return ResponseEntity.status(HttpStatus.CONFLICT).body(errorResponse);
    }// 다른 예외 처리기를 여기에 추가할 수 있습니다.
}