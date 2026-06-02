package com.school.auth.domain;

import com.school.common.audit.BaseEntity;
import jakarta.persistence.*;
import lombok.*;

/**
 * Local read-model of the permissions granted by each role, synchronized from
 * user-service via RabbitMQ ({@code role.permissions.changed} / {@code role.deleted}).
 * <p>
 * Combined with {@link UserRoleSnapshot}, it lets auth-service compute a user's
 * effective permissions at token-issue time without any synchronous call.
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Entity
@Table(name = "role_permission_snapshots",
        uniqueConstraints = @UniqueConstraint(name = "uk_role_perm_snapshot",
                columnNames = {"role_code", "permission_code"}))
public class RolePermissionSnapshot extends BaseEntity {

    @Column(name = "role_code", nullable = false, length = 50)
    private String roleCode;

    @Column(name = "permission_code", nullable = false, length = 100)
    private String permissionCode;
}