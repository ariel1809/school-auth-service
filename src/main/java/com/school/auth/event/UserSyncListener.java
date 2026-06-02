package com.school.auth.event;

import com.school.auth.domain.AuthUser;
import com.school.auth.domain.RolePermissionSnapshot;
import com.school.auth.domain.UserRoleSnapshot;
import com.school.auth.repository.AuthUserRepository;
import com.school.auth.repository.RefreshTokenRepository;
import com.school.auth.repository.RolePermissionSnapshotRepository;
import com.school.auth.repository.UserRoleSnapshotRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.amqp.core.Binding;
import org.springframework.amqp.core.BindingBuilder;
import org.springframework.amqp.core.Queue;
import org.springframework.amqp.core.TopicExchange;
import org.springframework.amqp.rabbit.annotation.RabbitListener;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Listens to user-service events to keep the local read-models in sync:
 *   - auth_users + user_role_snapshots  (who the user is, which roles)
 *   - role_permission_snapshots          (which permissions each role grants)
 *
 * Events expected:
 *   - user.created          : { id, email, fullName, initialPassword, roles[] }
 *   - user.updated          : { id, email, fullName, enabled }
 *   - user.roles.changed    : { userId, roles[] }
 *   - user.deleted          : { id }
 *   - role.permissions.changed : { roleCode, permissions[] }
 *   - role.deleted          : { roleCode }
 */
@Slf4j
@Configuration
@RequiredArgsConstructor
public class UserSyncListener {

    public static final String QUEUE = "auth.user-sync";
    public static final String EXCHANGE = "school.users";

    private final AuthUserRepository userRepo;
    private final UserRoleSnapshotRepository roleRepo;
    private final RolePermissionSnapshotRepository rolePermRepo;
    private final RefreshTokenRepository refreshRepo;
    private final PasswordEncoder passwordEncoder;

    @Bean
    public Queue userSyncQueue() {
        return new Queue(QUEUE, true);
    }

    @Bean
    public Binding userSyncBinding(Queue userSyncQueue, TopicExchange userExchange) {
        return BindingBuilder.bind(userSyncQueue).to(userExchange).with("user.#");
    }

    @Bean
    public Binding roleSyncBinding(Queue userSyncQueue, TopicExchange userExchange) {
        return BindingBuilder.bind(userSyncQueue).to(userExchange).with("role.#");
    }

    @RabbitListener(queues = QUEUE)
    @Transactional
    public void handle(Map<String, Object> event) {
        String type = (String) event.get("type");
        log.info("Received sync event {}", type);
        switch (type == null ? "" : type) {
            case "user.created" -> onCreated(event);
            case "user.updated" -> onUpdated(event);
            case "user.roles.changed" -> onRolesChanged(event);
            case "user.deleted" -> onDeleted(event);
            case "role.permissions.changed" -> onRolePermissionsChanged(event);
            case "role.deleted" -> onRoleDeleted(event);
            default -> log.debug("Ignoring event {}", type);
        }
    }

    private void onCreated(Map<String, Object> event) {
        UUID id = UUID.fromString((String) event.get("id"));
        if (userRepo.existsById(id)) return;
        String pwd = (String) event.getOrDefault("initialPassword", UUID.randomUUID().toString());
        AuthUser user = AuthUser.builder()
                .email(((String) event.get("email")).toLowerCase())
                .passwordHash(passwordEncoder.encode(pwd))
                .fullName((String) event.get("fullName"))
                .enabled(true)
                .emailVerified(false)
                .mfaEnabled(false)
                .failedLoginAttempts(0)
                .build();
        // Force the id from the upstream service for cross-service consistency
        user.setId(id);
        userRepo.save(user);
        syncRoles(id, (List<String>) event.get("roles"));
    }

    private void onUpdated(Map<String, Object> event) {
        UUID id = UUID.fromString((String) event.get("id"));
        userRepo.findById(id).ifPresent(u -> {
            if (event.get("email") != null) u.setEmail(((String) event.get("email")).toLowerCase());
            if (event.get("fullName") != null) u.setFullName((String) event.get("fullName"));
            if (event.get("enabled") != null) u.setEnabled((Boolean) event.get("enabled"));
        });
    }

    private void onRolesChanged(Map<String, Object> event) {
        UUID id = UUID.fromString((String) event.get("userId"));
        syncRoles(id, (List<String>) event.get("roles"));
        // A change in a user's roles immediately changes their authority set.
        // Revoke active sessions so the new role set takes effect on next login
        // (existing access tokens still expire naturally within their short TTL).
        int revoked = refreshRepo.revokeAllForUser(id, Instant.now());
        if (revoked > 0) {
            log.info("Revoked {} refresh token(s) for user {} after role change", revoked, id);
        }
    }

    private void onDeleted(Map<String, Object> event) {
        UUID id = UUID.fromString((String) event.get("id"));
        roleRepo.deleteAllByUserId(id);
        userRepo.deleteById(id);
    }

    private void onRolePermissionsChanged(Map<String, Object> event) {
        String roleCode = (String) event.get("roleCode");
        if (roleCode == null) return;
        List<String> permissions = (List<String>) event.get("permissions");
        Set<String> incoming = permissions == null ? Set.of() : new HashSet<>(permissions);

        List<RolePermissionSnapshot> existing = rolePermRepo.findAllByRoleCode(roleCode);
        Set<String> existingCodes = existing.stream()
                .map(RolePermissionSnapshot::getPermissionCode)
                .collect(Collectors.toSet());

        // remove permissions no longer granted
        existing.stream()
                .filter(s -> !incoming.contains(s.getPermissionCode()))
                .forEach(rolePermRepo::delete);
        // add newly granted permissions
        incoming.stream()
                .filter(p -> !existingCodes.contains(p))
                .forEach(p -> rolePermRepo.save(RolePermissionSnapshot.builder()
                        .roleCode(roleCode)
                        .permissionCode(p)
                        .build()));
    }

    private void onRoleDeleted(Map<String, Object> event) {
        String roleCode = (String) event.get("roleCode");
        if (roleCode != null) {
            rolePermRepo.deleteAllByRoleCode(roleCode);
        }
    }

    private void syncRoles(UUID userId, List<String> roles) {
        if (roles == null) return;
        Set<String> incoming = new HashSet<>(roles);
        Set<String> existing = roleRepo.findAllByUserId(userId).stream()
                .map(UserRoleSnapshot::getRoleCode)
                .collect(Collectors.toSet());
        // remove obsolete
        roleRepo.findAllByUserId(userId).stream()
                .filter(s -> !incoming.contains(s.getRoleCode()))
                .forEach(roleRepo::delete);
        // add new
        incoming.stream()
                .filter(r -> !existing.contains(r))
                .forEach(r -> roleRepo.save(UserRoleSnapshot.builder()
                        .userId(userId)
                        .roleCode(r)
                        .build()));
    }
}