package com.authcore.user;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface UserRepository extends JpaRepository<AuthCoreUser, UUID> {

    /**
     * The tenant-scoped lookup every authentication path must use. A username alone no
     * longer identifies a person, so resolving without a tenant would let a caller
     * authenticate against whichever tenant happened to be matched first.
     *
     * <p>Written out rather than derived from the method name: the derived parser reads
     * {@code TenantSlug} as a single property and cannot find it on the entity.
     */
    @Query("SELECT u FROM AuthCoreUser u WHERE u.tenant.slug = :tenantSlug AND u.username = :username")
    Optional<AuthCoreUser> findByTenantSlugAndUsername(@Param("tenantSlug") String tenantSlug,
                                                       @Param("username") String username);
}
