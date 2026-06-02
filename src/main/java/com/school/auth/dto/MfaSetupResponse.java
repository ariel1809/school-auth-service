package com.school.auth.dto;

public record MfaSetupResponse(
        String secret,
        String qrCodeDataUri
) {}