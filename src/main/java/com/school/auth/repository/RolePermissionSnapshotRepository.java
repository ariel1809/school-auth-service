package com.school.auth.repository;

import com.school.auth.domain.RolePermissionSnapshot;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.Collection;
import java.util.List;
import java.util.UUID;

public interface RolePermissionSnapshotRepository extends JpaRepository<RolePermissionSnapshot, UUID> {

    List<RolePermissionSnapshot> findAllByRoleCode(String roleCode);

    void deleteAllByRoleCode(String roleCode);

    /**
     * Effective permission codes for the given set of role codes (union, de-duplicated).
     */
    @Query("select distinct s.permissionCode from RolePermissionSnapshot s where s.roleCode in :roleCodes")
    List<String> findPermissionCodesByRoleCodes(Collection<String> roleCodes);
}