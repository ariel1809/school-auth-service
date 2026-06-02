package com.school.auth.service;

import com.school.auth.domain.AuthUser;
import com.school.auth.domain.PasswordResetToken;
import com.school.auth.domain.RefreshToken;
import com.school.auth.domain.UserRoleSnapshot;
import com.school.auth.dto.*;
import com.school.auth.event.AuditEventPublisher;
import com.school.auth.repository.AuthUserRepository;
import com.school.auth.repository.PasswordResetTokenRepository;
import com.school.auth.repository.RefreshTokenRepository;
import com.school.auth.repository.RolePermissionSnapshotRepository;
import com.school.auth.repository.UserRoleSnapshotRepository;
import com.school.common.exception.BusinessException;
import com.school.common.exception.ConflictException;
import com.school.common.exception.UnauthorizedException;
import com.school.common.security.JwtService;
import com.school.common.util.RequestContext;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private static final int MAX_FAILED_ATTEMPTS = 5;
    private static final Duration LOCK_DURATION = Duration.ofMinutes(15);
    private static final Duration PASSWORD_RESET_VALIDITY = Duration.ofMinutes(30);

    private final AuthUserRepository userRepo;
    private final RefreshTokenRepository refreshRepo;
    private final PasswordResetTokenRepository resetRepo;
    private final UserRoleSnapshotRepository roleRepo;
    private final RolePermissionSnapshotRepository rolePermRepo;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final TokenHasher tokenHasher;
    private final MfaService mfaService;
    private final MailService mailService;
    private final AuditEventPublisher audit;

    @Value("${app.frontend-url:http://localhost:5173}")
    private String frontendUrl;

    private final SecureRandom random = new SecureRandom();

    // ---------------- Login ----------------

    @Transactional
    public LoginResponse login(LoginRequest req) {
        AuthUser user = userRepo.findByEmailIgnoreCase(req.email())
                .orElseThrow(() -> new UnauthorizedException("Invalid email or password"));

        if (!user.isEnabled()) {
            audit.publishFailedLogin(user.getId(), req.email(), "USER_DISABLED");
            throw new BusinessException("USER_DISABLED", "Account is disabled", HttpStatus.FORBIDDEN);
        }

        if (user.isLocked()) {
            audit.publishFailedLogin(user.getId(), req.email(), "USER_LOCKED");
            throw new BusinessException("USER_LOCKED",
                    "Too many failed attempts. Try again later.", HttpStatus.LOCKED);
        }

        if (!passwordEncoder.matches(req.password(), user.getPasswordHash())) {
            user.setFailedLoginAttempts(user.getFailedLoginAttempts() + 1);
            if (user.getFailedLoginAttempts() >= MAX_FAILED_ATTEMPTS) {
                user.setLockedUntil(Instant.now().plus(LOCK_DURATION));
                log.warn("Locked user {} after {} failed attempts", user.getId(), user.getFailedLoginAttempts());
            }
            audit.publishFailedLogin(user.getId(), req.email(), "BAD_PASSWORD");
            throw new UnauthorizedException("Invalid email or password");
        }

        if (user.isMfaEnabled()) {
            if (req.mfaCode() == null || req.mfaCode().isBlank()) {
                return LoginResponse.mfaChallenge();
            }
            if (mfaService.verify(user.getMfaSecret(), req.mfaCode())) {
                audit.publishFailedLogin(user.getId(), req.email(), "BAD_MFA_CODE");
                throw new UnauthorizedException("Invalid MFA code");
            }
        }

        user.setFailedLoginAttempts(0);
        user.setLockedUntil(null);
        user.setLastLoginAt(Instant.now());
        user.setLastLoginIp(RequestContext.clientIp());

        return issueTokens(user);
    }

    private LoginResponse issueTokens(AuthUser user) {
        Set<String> roles = roleRepo.findAllByUserId(user.getId()).stream()
                .map(UserRoleSnapshot::getRoleCode)
                .collect(Collectors.toSet());
        // Effective permissions = union of the permissions granted by the user's roles,
        // resolved from the locally synchronized role_permission_snapshots read-model.
        Set<String> permissions = roles.isEmpty()
                ? Set.of()
                : Set.copyOf(rolePermRepo.findPermissionCodesByRoleCodes(roles));

        String access = jwtService.issueAccessToken(
                user.getId(), user.getEmail(), user.getFullName(), roles, permissions);

        String rawRefresh = generateOpaqueToken();
        String sessionId = UUID.randomUUID().toString();
        Instant expiresAt = Instant.now().plusMillis(jwtService.getRefreshTokenExpirationMs());

        RefreshToken rt = RefreshToken.builder()
                .userId(user.getId())
                .tokenHash(tokenHasher.hash(rawRefresh))
                .expiresAt(expiresAt)
                .userAgent(truncate(RequestContext.userAgent(), 500))
                .ipAddress(RequestContext.clientIp())
                .build();
        refreshRepo.save(rt);

        audit.publishSuccessfulLogin(user.getId(), user.getEmail());

        return LoginResponse.builder()
                .accessToken(access)
                .refreshToken(rawRefresh)
                .accessTokenExpiresInMs(jwtService.getAccessTokenExpirationMs())
                .userId(user.getId())
                .email(user.getEmail())
                .fullName(user.getFullName())
                .roles(roles)
                .permissions(permissions)
                .build();
    }

    // ---------------- Refresh ----------------

    @Transactional
    public LoginResponse refresh(RefreshRequest req) {
        String hash = tokenHasher.hash(req.refreshToken());
        RefreshToken rt = refreshRepo.findByTokenHash(hash)
                .orElseThrow(() -> new UnauthorizedException("Invalid refresh token"));
        if (!rt.isActive()) {
            throw new UnauthorizedException("Refresh token expired or revoked");
        }
        AuthUser user = userRepo.findById(rt.getUserId())
                .orElseThrow(() -> new UnauthorizedException("User not found"));

        // Rotate: revoke old, issue new
        rt.setRevokedAt(Instant.now());
        return issueTokens(user);
    }

    // ---------------- Logout ----------------

    @Transactional
    public void logout(String refreshToken) {
        if (refreshToken == null || refreshToken.isBlank()) return;
        String hash = tokenHasher.hash(refreshToken);
        refreshRepo.findByTokenHash(hash).ifPresent(rt -> {
            if (rt.getRevokedAt() == null) {
                rt.setRevokedAt(Instant.now());
                audit.publishLogout(rt.getUserId());
            }
        });
    }

    // ---------------- Forgot / Reset password ----------------

    @Transactional
    public void requestPasswordReset(ForgotPasswordRequest req) {
        // Always answer 200 — don't leak whether the email exists
        userRepo.findByEmailIgnoreCase(req.email()).ifPresent(user -> {
            String raw = generateOpaqueToken();
            PasswordResetToken token = PasswordResetToken.builder()
                    .userId(user.getId())
                    .tokenHash(tokenHasher.hash(raw))
                    .expiresAt(Instant.now().plus(PASSWORD_RESET_VALIDITY))
                    .build();
            resetRepo.save(token);

            String link = frontendUrl + "/reset-password?token=" + raw;
            mailService.sendPasswordResetEmail(user.getEmail(), user.getFullName(), link);
            audit.publishPasswordResetRequested(user.getId());
        });
    }

    @Transactional
    public void resetPassword(ResetPasswordRequest req) {
        String hash = tokenHasher.hash(req.token());
        PasswordResetToken token = resetRepo.findByTokenHash(hash)
                .orElseThrow(() -> new BusinessException("INVALID_TOKEN", "Invalid reset token"));
        if (!token.isValid()) {
            throw new BusinessException("EXPIRED_TOKEN", "Reset link has expired");
        }
        AuthUser user = userRepo.findById(token.getUserId())
                .orElseThrow(() -> new BusinessException("USER_NOT_FOUND", "User not found"));

        user.setPasswordHash(passwordEncoder.encode(req.newPassword()));
        user.setFailedLoginAttempts(0);
        user.setLockedUntil(null);
        token.setUsedAt(Instant.now());
        refreshRepo.revokeAllForUser(user.getId(), Instant.now());
        audit.publishPasswordChanged(user.getId());
    }

    @Transactional
    public void changePassword(UUID userId, ChangePasswordRequest req) {
        AuthUser user = userRepo.findById(userId)
                .orElseThrow(() -> new UnauthorizedException("User not found"));
        if (!passwordEncoder.matches(req.currentPassword(), user.getPasswordHash())) {
            throw new UnauthorizedException("Current password is incorrect");
        }
        user.setPasswordHash(passwordEncoder.encode(req.newPassword()));
        refreshRepo.revokeAllForUser(user.getId(), Instant.now());
        audit.publishPasswordChanged(user.getId());
    }

    // ---------------- MFA ----------------

    @Transactional
    public MfaSetupResponse setupMfa(UUID userId) {
        AuthUser user = userRepo.findById(userId)
                .orElseThrow(() -> new UnauthorizedException("User not found"));
        if (user.isMfaEnabled()) {
            throw new ConflictException("MFA_ALREADY_ENABLED", "MFA is already enabled");
        }
        String secret = mfaService.generateSecret();
        user.setMfaSecret(secret);
        return new MfaSetupResponse(secret, mfaService.generateQrCodeDataUri(user.getEmail(), secret));
    }

    @Transactional
    public void confirmMfa(UUID userId, MfaVerifyRequest req) {
        AuthUser user = userRepo.findById(userId)
                .orElseThrow(() -> new UnauthorizedException("User not found"));
        if (user.getMfaSecret() == null) {
            throw new BusinessException("MFA_NOT_SETUP", "Run setup first");
        }
        if (mfaService.verify(user.getMfaSecret(), req.code())) {
            throw new BusinessException("BAD_MFA_CODE", "Invalid MFA code");
        }
        user.setMfaEnabled(true);
        audit.publishMfaEnabled(user.getId());
    }

    @Transactional
    public void disableMfa(UUID userId, MfaVerifyRequest req) {
        AuthUser user = userRepo.findById(userId)
                .orElseThrow(() -> new UnauthorizedException("User not found"));
        if (!user.isMfaEnabled()) return;
        if (mfaService.verify(user.getMfaSecret(), req.code())) {
            throw new BusinessException("BAD_MFA_CODE", "Invalid MFA code");
        }
        user.setMfaEnabled(false);
        user.setMfaSecret(null);
        audit.publishMfaDisabled(user.getId());
    }

    // ---------------- Bootstrap ----------------

    /**
     * One-time creation of the very first Super Admin when the DB is empty.
     * Used during initial setup before any user exists.
     */
    @Transactional
    public UUID bootstrapSuperAdmin(String email, String fullName, String password) {
        if (userRepo.count() > 0) {
            throw new ConflictException("ALREADY_BOOTSTRAPPED",
                    "An initial admin already exists. Use the standard user creation flow.");
        }
        AuthUser user = AuthUser.builder()
                .email(email.toLowerCase())
                .passwordHash(passwordEncoder.encode(password))
                .fullName(fullName)
                .enabled(true)
                .emailVerified(true)
                .mfaEnabled(false)
                .failedLoginAttempts(0)
                .build();
        userRepo.save(user);
        roleRepo.save(UserRoleSnapshot.builder()
                .userId(user.getId())
                .roleCode("SUPER_ADMIN")
                .build());
        audit.publishUserBootstrapped(user.getId(), user.getEmail());
        return user.getId();
    }

    // ---------------- Helpers ----------------

    private String generateOpaqueToken() {
        byte[] buf = new byte[48];
        random.nextBytes(buf);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(buf);
    }

    private static String truncate(String s, int max) {
        if (s == null) return null;
        return s.length() <= max ? s : s.substring(0, max);
    }
}
