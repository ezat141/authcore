package com.authcore.security;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Turns the three authorization claims into authorities.
 *
 * <p>Spring's default converter reads {@code scope} only. That is enough for a client
 * asking "may I call this API?", but {@code @PreAuthorize("hasAuthority('payments:write')")}
 * and {@code hasRole('ADMIN')} are asking about the user, whose capabilities ride in the
 * {@code permissions} and {@code roles} claims that {@link com.authcore.token.AuthCoreTokenCustomizer}
 * writes. Without this converter those claims would be visible in the token but
 * unenforced — decoration rather than authorization.
 *
 * <p>All three are kept, not merged: scope stays the client's delegated ceiling, while
 * roles and permissions describe the user. A request is only permitted when both agree.
 */
public class AuthCoreJwtAuthoritiesConverter implements Converter<Jwt, Collection<GrantedAuthority>> {

    @Override
    public Collection<GrantedAuthority> convert(Jwt jwt) {
        Set<GrantedAuthority> authorities = new LinkedHashSet<>();

        // scope -> SCOPE_*, matching Spring's default so M4's URL rules keep working.
        for (String scope : claimAsList(jwt, "scope")) {
            authorities.add(new SimpleGrantedAuthority("SCOPE_" + scope));
        }
        // roles are stored bare in the claim; hasRole() expects the prefix.
        for (String role : claimAsList(jwt, "roles")) {
            authorities.add(new SimpleGrantedAuthority(
                    role.startsWith("ROLE_") ? role : "ROLE_" + role));
        }
        // permissions are already the exact string hasAuthority() checks.
        for (String permission : claimAsList(jwt, "permissions")) {
            authorities.add(new SimpleGrantedAuthority(permission));
        }

        return authorities;
    }

    /** The {@code scope} claim may arrive as a list or as a space-delimited string. */
    private static List<String> claimAsList(Jwt jwt, String claimName) {
        Object claim = jwt.getClaim(claimName);
        if (claim == null) {
            return List.of();
        }
        if (claim instanceof Collection<?> collection) {
            return collection.stream().map(String::valueOf).toList();
        }
        String value = String.valueOf(claim).trim();
        return value.isEmpty() ? List.of() : List.of(value.split("\\s+"));
    }
}
