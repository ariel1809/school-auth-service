package com.school.auth.config;

import com.school.common.security.JwtService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class JwtConfig {

    @Bean
    public JwtService jwtService(
            @Value("${jwt.secret}") String secret,
            @Value("${jwt.access-token-expiration-ms:900000}") long accessExpMs,
            @Value("${jwt.refresh-token-expiration-ms:604800000}") long refreshExpMs) {
        return new JwtService(secret, accessExpMs, refreshExpMs);
    }
}