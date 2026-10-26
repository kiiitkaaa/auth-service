package com.deshko.authservice.dto;

import jakarta.validation.constraints.NotBlank;

public record ValidateRequest(
        @NotBlank
        String token
) {}
