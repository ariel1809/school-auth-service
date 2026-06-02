package com.school.auth.domain;

import com.school.common.audit.BaseEntity;
import jakarta.persistence.*;
import lombok.*;

import java.util.UUID;

/**
 * Local read-model of the roles/permissions a user has, synchronized
 * from user-service via RabbitMQ events. Keeps auth-service self-contained
 * for token issuance without a synchronous call.
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Entity
@Table(name = "user_role_snapshots",
        uniqueConstraints = @UniqueConstraint(name = "uk_user_role_snapshot_user_role",
                columnNames = {"user_id", "role_code"}))
public class UserRoleSnapshot extends BaseEntity {

    @Column(name = "user_id", nullable = false)
    private UUID userId;

    @Column(name = "role_code", nullable = false, length = 50)
    private String roleCode;
}