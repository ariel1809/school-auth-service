package com.school.auth.dto;

import lombok.Builder;

import java.util.Set;
import java.util.UUID;

@Builder
public record LoginResponse(
        String accessToken,
        String refreshToken,
        long accessTokenExpiresInMs,
        boolean mfaRequired,
        UUID userId,
        String email,
        String fullName,
        Set<String> roles,
        Set<String> permissions
) {
    public static LoginResponse mfaChallenge() {
        return LoginResponse.builder().mfaRequired(true).build();
    }
}