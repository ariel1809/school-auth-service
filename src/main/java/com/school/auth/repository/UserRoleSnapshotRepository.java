package com.school.auth.repository;

import com.school.auth.domain.UserRoleSnapshot;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.UUID;

public interface UserRoleSnapshotRepository extends JpaRepository<UserRoleSnapshot, UUID> {
    List<UserRoleSnapshot> findAllByUserId(UUID userId);

    void deleteAllByUserId(UUID userId);
}