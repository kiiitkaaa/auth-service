package com.deshko.authservice.dto;

import jakarta.validation.constraints.NotBlank;

public record LoginRequest(
        @NotBlank
        String login,

        @NotBlank
        String password
) {}
