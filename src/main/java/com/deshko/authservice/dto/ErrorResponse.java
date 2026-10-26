package com.deshko.authservice.dto;

import org.springframework.http.HttpStatus;
import java.time.Instant;

public record ErrorResponse(int status, String message, Instant timestamp) {
    public static ErrorResponse of(HttpStatus status, String message) {
        return new ErrorResponse(status.value(), message, Instant.now());
    }
}