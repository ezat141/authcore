package com.authcore.apikey;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Set;
import java.util.stream.Collectors;

/**
 * Validates an API key and turns its scopes into authorities.
 *
 * <p>Scopes become {@code SCOPE_*} authorities — the same shape Spring gives a JWT's
 * {@code scope} claim. That is deliberate: an endpoint can be guarded by a single
 * {@code hasAuthority("SCOPE_payments:read")} rule and accept either a bearer token
 * or an API key, with no branching on how the caller authenticated.
 */
public class ApiKeyAuthenticationProvider implements AuthenticationProvider {

    private final ApiKeyStore apiKeyStore;

    public ApiKeyAuthenticationProvider(ApiKeyStore apiKeyStore) {
        this.apiKeyStore = apiKeyStore;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        ApiKeyAuthenticationToken request = (ApiKeyAuthenticationToken) authentication;
        String rawKey = (String) request.getCredentials();

        ApiKey apiKey = apiKeyStore.findByRawKey(rawKey)
                .orElseThrow(() -> new BadCredentialsException("Unknown API key"));

        // Distinguish these two so operators can tell a revoked key from a lapsed one
        // in the logs; the caller still just sees 401.
        if (!apiKey.enabled()) {
            throw new DisabledException("API key is disabled: " + apiKey.name());
        }
        if (apiKey.isExpired()) {
            throw new CredentialsExpiredException("API key has expired: " + apiKey.name());
        }

        Set<SimpleGrantedAuthority> authorities = apiKey.scopes().stream()
                .map(scope -> new SimpleGrantedAuthority("SCOPE_" + scope))
                .collect(Collectors.toSet());

        apiKeyStore.touchLastUsed(apiKey.id());

        return new ApiKeyAuthenticationToken(apiKey, authorities);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return ApiKeyAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
