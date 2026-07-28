package com.authcore;

import com.authcore.tenant.TenantContext;
import com.authcore.token.AuthCoreTokenCustomizer;
import com.authcore.user.AuthCoreUserPrincipal;
import com.authcore.user.UserRepository;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;

import java.time.Instant;
import java.util.Collection;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Regression cover for a real defect: the tenant claim was read from
 * {@link TenantContext}, which is empty during {@code /oauth2/token} because that request
 * comes from the client's backend rather than the user's browser. Every token was
 * therefore stamped {@code tenant=default} regardless of who logged in.
 *
 * <p>The first test reproduces exactly that situation — a request context pointing at the
 * wrong tenant — and asserts the claim follows the principal instead.
 */
@SpringBootTest
@Import(TestcontainersConfiguration.class)
class TokenCustomizerTenantTest {

    @Autowired
    private UserRepository userRepository;

    @AfterEach
    void clearTenant() {
        TenantContext.clear();
    }

    @Test
    void tenantClaimComesFromThePrincipalNotTheRequestContext() {
        // The token request looks like it belongs to 'default' — as it always does,
        // since curl and backend clients send no tenant hint at all.
        TenantContext.set("default");

        JwtEncodingContext context = contextFor(principal("ezzat", "acme"));
        new AuthCoreTokenCustomizer(userRepository).customize(context);

        JwtClaimsSet claims = context.getClaims().build();
        String tenantClaim = claims.getClaim("tenant");
        assertThat(tenantClaim).isEqualTo("acme");
    }

    @Test
    void claimsResolveAgainstTheUsersOwnTenant() {
        TenantContext.set("acme");

        // Both tenants have an 'ezzat'; the default one is ROLE_USER with no admin rights.
        JwtEncodingContext context = contextFor(principal("admin", "default"));
        new AuthCoreTokenCustomizer(userRepository).customize(context);

        JwtClaimsSet claims = context.getClaims().build();
        String tenantClaim = claims.getClaim("tenant");
        Collection<String> roles = claims.getClaim("roles");
        assertThat(tenantClaim).isEqualTo("default");
        assertThat(roles).contains("ADMIN");
    }

    @Test
    void tokensWithNoUserPrincipalGetNoTenantClaim() {
        // Client credentials: the principal is the client, not a person.
        Authentication clientPrincipal =
                new UsernamePasswordAuthenticationToken("authcore-machine", "n/a", List.of());

        JwtEncodingContext context = contextFor(clientPrincipal);
        new AuthCoreTokenCustomizer(userRepository).customize(context);

        JwtClaimsSet claims = context.getClaims().build();
        String tenantClaim = claims.getClaim("tenant");
        Collection<String> roles = claims.getClaim("roles");
        assertThat(tenantClaim).isNull();
        assertThat(roles).isNull();
    }

    private static Authentication principal(String username, String tenantSlug) {
        AuthCoreUserPrincipal user =
                new AuthCoreUserPrincipal(username, "{noop}x", tenantSlug, true, List.of());
        return new UsernamePasswordAuthenticationToken(user, "n/a", List.of());
    }

    private static JwtEncodingContext contextFor(Authentication principal) {
        return JwtEncodingContext
                .with(org.springframework.security.oauth2.jwt.JwsHeader.with(
                                org.springframework.security.oauth2.jose.jws.SignatureAlgorithm.RS256),
                        JwtClaimsSet.builder()
                                .subject(principal.getName())
                                .issuedAt(Instant.now())
                                .expiresAt(Instant.now().plusSeconds(300)))
                .principal(principal)
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .build();
    }
}
