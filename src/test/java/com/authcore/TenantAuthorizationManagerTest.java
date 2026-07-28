package com.authcore;

import com.authcore.tenant.TenantAuthorizationManager;
import com.authcore.tenant.TenantContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * A correctly signed token is still the wrong token if it came from another tenant.
 */
class TenantAuthorizationManagerTest {

    private final AuthorizationManager<RequestAuthorizationContext> allow =
            (auth, ctx) -> new AuthorizationDecision(true);

    private final TenantAuthorizationManager manager = new TenantAuthorizationManager(allow);

    @AfterEach
    void clearTenant() {
        TenantContext.clear();
    }

    @Test
    void tokenIsAcceptedInTheTenantItWasIssuedFor() {
        TenantContext.set("acme");

        AuthorizationResult result = manager.authorize(() -> jwtFor("acme"), null);

        assertThat(result.isGranted()).isTrue();
    }

    @Test
    void tokenFromAnotherTenantIsRefusedEvenThoughItIsValid() {
        // The token is genuine and unexpired — it is simply being used in the wrong place.
        TenantContext.set("default");

        AuthorizationResult result = manager.authorize(() -> jwtFor("acme"), null);

        assertThat(result.isGranted()).isFalse();
    }

    @Test
    void aDenialFromTheDelegateIsNotOverturned() {
        AuthorizationManager<RequestAuthorizationContext> deny =
                (auth, ctx) -> new AuthorizationDecision(false);
        TenantContext.set("acme");

        AuthorizationResult result =
                new TenantAuthorizationManager(deny).authorize(() -> jwtFor("acme"), null);

        assertThat(result.isGranted()).isFalse();
    }

    @Test
    void callersWithNoTenantClaimAreLeftToTheOtherRules() {
        // Client-credentials tokens and API keys are not tenant-bound; there is
        // nothing to compare, so this manager must not invent a reason to deny.
        TenantContext.set("acme");

        AuthorizationResult jwtWithoutClaim = manager.authorize(() -> jwtFor(null), null);
        AuthorizationResult apiKeyStyle = manager.authorize(
                () -> new UsernamePasswordAuthenticationToken("demo-key", "n/a", List.of()), null);

        assertThat(jwtWithoutClaim.isGranted()).isTrue();
        assertThat(apiKeyStyle.isGranted()).isTrue();
    }

    private static Authentication jwtFor(String tenant) {
        Jwt.Builder builder = Jwt.withTokenValue("token")
                .header("alg", "RS256")
                .subject("ezzat")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(300));
        if (tenant != null) {
            builder.claim("tenant", tenant);
        }
        return new JwtAuthenticationToken(builder.build(),
                List.of(new SimpleGrantedAuthority("SCOPE_payments:read")));
    }
}
