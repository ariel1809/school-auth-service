package com.school.auth.event;

import com.school.common.util.RequestContext;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

@Slf4j
@Component
@RequiredArgsConstructor
public class AuditEventPublisher {

    public static final String EXCHANGE = "school.audit";
    public static final String ROUTING_AUTH = "audit.auth";

    private final RabbitTemplate rabbit;

    @Value("${spring.rabbitmq.host:}")
    private String rabbitHost;

    public void publishSuccessfulLogin(UUID userId, String email) {
        publish("AUTH_LOGIN_SUCCESS", userId, Map.of("email", email));
    }

    public void publishFailedLogin(UUID userId, String email, String reason) {
        publish("AUTH_LOGIN_FAILED", userId,
                Map.of("email", email, "reason", reason));
    }

    public void publishLogout(UUID userId) {
        publish("AUTH_LOGOUT", userId, Map.of());
    }

    public void publishPasswordResetRequested(UUID userId) {
        publish("AUTH_PASSWORD_RESET_REQUESTED", userId, Map.of());
    }

    public void publishPasswordChanged(UUID userId) {
        publish("AUTH_PASSWORD_CHANGED", userId, Map.of());
    }

    public void publishMfaEnabled(UUID userId) {
        publish("AUTH_MFA_ENABLED", userId, Map.of());
    }

    public void publishMfaDisabled(UUID userId) {
        publish("AUTH_MFA_DISABLED", userId, Map.of());
    }

    public void publishUserBootstrapped(UUID userId, String email) {
        publish("AUTH_USER_BOOTSTRAPPED", userId, Map.of("email", email));
    }

    private void publish(String type, UUID userId, Map<String, Object> details) {
        Map<String, Object> event = Map.of(
                "type", type,
                "userId", userId == null ? null : userId.toString(),
                "ipAddress", RequestContext.clientIp(),
                "userAgent", RequestContext.userAgent(),
                "details", details,
                "timestamp", Instant.now().toString()
        );
        try {
            if (rabbitHost == null || rabbitHost.isBlank()) {
                log.debug("[audit] {}", event);
                return;
            }
            rabbit.convertAndSend(EXCHANGE, ROUTING_AUTH, event);
        } catch (Exception ex) {
            // never block auth flow on audit publish failure
            log.warn("Failed to publish audit event {}: {}", type, ex.getMessage());
        }
    }
}