package com.deshko.authservice.dto;

public record ValidateResponse(
        boolean valid,
        Long userId,
        String role
) {}