package com.authcore.tenant;

import org.springframework.stereotype.Service;

import java.util.Optional;

/**
 * Tenant lookups for the request path.
 *
 * <p>{@link #exists(String)} runs on every request, so it deliberately treats a disabled
 * tenant as non-existent: suspending a tenant should stop its logins immediately rather
 * than letting sessions continue until they expire.
 */
@Service
public class TenantService {

    private final TenantRepository tenantRepository;

    public TenantService(TenantRepository tenantRepository) {
        this.tenantRepository = tenantRepository;
    }

    public boolean exists(String slug) {
        return tenantRepository.findBySlug(slug)
                .filter(Tenant::isEnabled)
                .isPresent();
    }

    public Optional<Tenant> findBySlug(String slug) {
        return tenantRepository.findBySlug(slug);
    }

    public Tenant requireCurrent() {
        String slug = TenantContext.get();
        return tenantRepository.findBySlug(slug)
                .orElseThrow(() -> new IllegalStateException("Unknown tenant: " + slug));
    }
}
