package com.school.auth.web;

import com.school.auth.dto.*;
import com.school.auth.service.AuthService;
import com.school.common.dto.ApiResponse;
import com.school.common.security.AuthenticatedUser;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
@Validated
public class AuthController {

    private final AuthService authService;

    @PostMapping("/login")
    public ApiResponse<LoginResponse> login(@Valid @RequestBody LoginRequest req) {
        return ApiResponse.ok(authService.login(req));
    }

    @PostMapping("/refresh")
    public ApiResponse<LoginResponse> refresh(@Valid @RequestBody RefreshRequest req) {
        return ApiResponse.ok(authService.refresh(req));
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@RequestBody(required = false) RefreshRequest req) {
        if (req != null) authService.logout(req.refreshToken());
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/forgot-password")
    public ApiResponse<Void> forgotPassword(@Valid @RequestBody ForgotPasswordRequest req) {
        authService.requestPasswordReset(req);
        return ApiResponse.ok(null, "If an account exists, a reset link has been sent.");
    }

    @PostMapping("/reset-password")
    public ApiResponse<Void> resetPassword(@Valid @RequestBody ResetPasswordRequest req) {
        authService.resetPassword(req);
        return ApiResponse.ok(null, "Password has been reset.");
    }

    @PostMapping("/change-password")
    public ApiResponse<Void> changePassword(@AuthenticationPrincipal AuthenticatedUser user,
                                            @Valid @RequestBody ChangePasswordRequest req) {
        authService.changePassword(user.getId(), req);
        return ApiResponse.ok(null, "Password changed.");
    }

    @PostMapping("/mfa/setup")
    public ApiResponse<MfaSetupResponse> setupMfa(@AuthenticationPrincipal AuthenticatedUser user) {
        return ApiResponse.ok(authService.setupMfa(user.getId()));
    }

    @PostMapping("/mfa/confirm")
    public ApiResponse<Void> confirmMfa(@AuthenticationPrincipal AuthenticatedUser user,
                                        @Valid @RequestBody MfaVerifyRequest req) {
        authService.confirmMfa(user.getId(), req);
        return ApiResponse.ok(null, "MFA enabled.");
    }

    @PostMapping("/mfa/disable")
    public ApiResponse<Void> disableMfa(@AuthenticationPrincipal AuthenticatedUser user,
                                        @Valid @RequestBody MfaVerifyRequest req) {
        authService.disableMfa(user.getId(), req);
        return ApiResponse.ok(null, "MFA disabled.");
    }

    @GetMapping("/me")
    public ApiResponse<Map<String, Object>> me(@AuthenticationPrincipal AuthenticatedUser user) {
        return ApiResponse.ok(Map.of(
                "id", user.getId(),
                "email", user.getEmail(),
                "fullName", user.getFullName(),
                "roles", user.getRoles(),
                "permissions", user.getPermissions()
        ));
    }

    @PostMapping("/bootstrap")
    public ApiResponse<Map<String, Object>> bootstrap(@Valid @RequestBody BootstrapRequest req) {
        UUID id = authService.bootstrapSuperAdmin(req.email(), req.fullName(), req.password());
        return ApiResponse.ok(Map.of("id", id, "email", req.email()),
                "Initial Super Admin created.");
    }

    public record BootstrapRequest(
            @Email @NotBlank String email,
            @NotBlank String fullName,
            @NotBlank @Size(min = 8, max = 128) String password
    ) {}
}