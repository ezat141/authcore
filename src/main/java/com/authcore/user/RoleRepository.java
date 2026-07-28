package com.authcore.user;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface RoleRepository extends JpaRepository<Role, UUID> {

    @Query("SELECT r FROM Role r WHERE r.tenant.slug = :tenantSlug AND r.name = :name")
    Optional<Role> findByTenantSlugAndName(@Param("tenantSlug") String tenantSlug,
                                           @Param("name") String name);
}
