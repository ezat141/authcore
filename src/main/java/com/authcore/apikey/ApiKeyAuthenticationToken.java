package com.authcore.apikey;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.List;

public class ApiKeyAuthenticationToken extends AbstractAuthenticationToken {

    private final String rawKey;
    private final ApiKey apiKey;

    /** Unauthenticated: what the filter builds from the request header. */
    public ApiKeyAuthenticationToken(String rawKey) {
        super(List.of());
        this.rawKey = rawKey;
        this.apiKey = null;
        setAuthenticated(false);
    }

    /** Authenticated: what the provider returns once the key checks out. */
    public ApiKeyAuthenticationToken(ApiKey apiKey, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.rawKey = null;
        this.apiKey = apiKey;
        setAuthenticated(true);
    }

    @Override
    public Object getCredentials() {
        return rawKey;
    }

    @Override
    public Object getPrincipal() {
        return apiKey != null ? apiKey.name() : null;
    }

    public ApiKey getApiKey() {
        return apiKey;
    }
}
