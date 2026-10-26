package com.deshko.authservice.dto;

public record TokenPair(
        String accessToken,
        String refreshToken
) {}
