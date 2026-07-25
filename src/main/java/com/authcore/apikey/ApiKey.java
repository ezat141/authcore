package com.authcore.apikey;

import java.time.Instant;
import java.util.Set;

public record ApiKey(
        String id,
        String name,
        String keyPrefix,
        Set<String> scopes,
        boolean enabled,
        Instant expiresAt) {

    public boolean isExpired() {
        return expiresAt != null && expiresAt.isBefore(Instant.now());
    }

    public boolean isUsable() {
        return enabled && !isExpired();
    }
}
