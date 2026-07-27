package com.authcore;

import com.authcore.security.AuthCoreJwtAuthoritiesConverter;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class JwtAuthoritiesConverterTest {

    private final AuthCoreJwtAuthoritiesConverter converter = new AuthCoreJwtAuthoritiesConverter();

    @Test
    void scopesRolesAndPermissionsAllBecomeAuthorities() {
        Jwt jwt = jwt(Map.of(
                "scope", List.of("openid", "payments:read"),
                "roles", List.of("USER"),
                "permissions", List.of("payments:read", "accounts:read")));

        assertThat(names(converter.convert(jwt))).containsExactlyInAnyOrder(
                "SCOPE_openid",
                "SCOPE_payments:read",
                "ROLE_USER",
                "payments:read",
                "accounts:read");
    }

    @Test
    void spaceDelimitedScopeStringIsSupported() {
        // Some issuers emit scope as one space-delimited string rather than a list.
        Jwt jwt = jwt(Map.of("scope", "openid payments:read"));

        assertThat(names(converter.convert(jwt)))
                .containsExactlyInAnyOrder("SCOPE_openid", "SCOPE_payments:read");
    }

    @Test
    void rolesAreNotDoublePrefixed() {
        Jwt jwt = jwt(Map.of("roles", List.of("ROLE_ADMIN", "USER")));

        assertThat(names(converter.convert(jwt)))
                .containsExactlyInAnyOrder("ROLE_ADMIN", "ROLE_USER");
    }

    @Test
    void missingClaimsYieldNoAuthoritiesRatherThanFailing() {
        // A client-credentials token has no user, so no roles or permissions claims.
        Jwt jwt = jwt(Map.of("sub", "authcore-machine"));

        assertThat(converter.convert(jwt)).isEmpty();
    }

    private static List<String> names(Collection<GrantedAuthority> authorities) {
        return authorities.stream().map(GrantedAuthority::getAuthority).toList();
    }

    private static Jwt jwt(Map<String, Object> claims) {
        Jwt.Builder builder = Jwt.withTokenValue("token")
                .header("alg", "RS256")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(300));
        claims.forEach(builder::claim);
        if (!claims.containsKey("sub")) {
            builder.subject("ezzat");
        }
        return builder.build();
    }
}
