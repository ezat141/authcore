package com.authcore;

import com.authcore.security.AuthCorePermissionEvaluator;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The owner-vs-admin distinction is the whole point of the evaluator, so each
 * combination of (holds permission, owns record, holds :all) is pinned down.
 */
class PermissionEvaluatorTest {

    private final AuthCorePermissionEvaluator evaluator = new AuthCorePermissionEvaluator();

    @Test
    void ownerWithPermissionCanReadTheirOwnAccount() {
        Authentication ezzat = user("ezzat", "accounts:read");

        assertThat(evaluator.hasPermission(ezzat, "ezzat", "Account", "read")).isTrue();
    }

    @Test
    void ownerWithPermissionCannotReadSomeoneElsesAccount() {
        Authentication ezzat = user("ezzat", "accounts:read");

        assertThat(evaluator.hasPermission(ezzat, "someone-else", "Account", "read")).isFalse();
    }

    @Test
    void adminWithAllPermissionCanReadAnyAccount() {
        Authentication admin = user("admin", "accounts:read", "accounts:read:all");

        assertThat(evaluator.hasPermission(admin, "ezzat", "Account", "read")).isTrue();
        assertThat(evaluator.hasPermission(admin, "admin", "Account", "read")).isTrue();
    }

    @Test
    void allPermissionAloneIsEnoughEvenWithoutTheBasePermission() {
        Authentication auditor = user("auditor", "accounts:read:all");

        assertThat(evaluator.hasPermission(auditor, "ezzat", "Account", "read")).isTrue();
    }

    @Test
    void callerWithoutTheRelevantPermissionIsDeniedEvenOnTheirOwnRecord() {
        Authentication nobody = user("ezzat", "payments:read");

        assertThat(evaluator.hasPermission(nobody, "ezzat", "Account", "read")).isFalse();
    }

    @Test
    void unauthenticatedCallerIsAlwaysDenied() {
        Authentication anonymous = new UsernamePasswordAuthenticationToken("ezzat", null);
        // No authorities granted -> isAuthenticated() is false for this constructor.

        assertThat(evaluator.hasPermission(anonymous, "ezzat", "Account", "read")).isFalse();
        assertThat(evaluator.hasPermission(null, "ezzat", "Account", "read")).isFalse();
    }

    private Authentication user(String username, String... authorities) {
        List<SimpleGrantedAuthority> granted = Arrays.stream(authorities)
                .map(SimpleGrantedAuthority::new)
                .toList();
        return new UsernamePasswordAuthenticationToken(username, "n/a", granted);
    }
}
