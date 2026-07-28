package com.authcore;

import com.authcore.tenant.TenantContext;
import com.authcore.user.AuthCoreUserDetailsService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The isolation guarantee, tested at the point it is enforced: user resolution.
 *
 * <p>Seeded fixture — {@code default} has ezzat and admin; {@code acme} has its own
 * ezzat plus alice.
 */
@SpringBootTest
@Import(TestcontainersConfiguration.class)
class TenantIsolationTest {

    @Autowired
    private AuthCoreUserDetailsService userDetailsService;

    @AfterEach
    void clearTenant() {
        TenantContext.clear();
    }

    @Test
    void userFromOneTenantIsInvisibleInAnother() {
        // alice exists only in acme.
        TenantContext.set("default");

        assertThatThrownBy(() -> userDetailsService.loadUserByUsername("alice"))
                .isInstanceOf(UsernameNotFoundException.class);
    }

    @Test
    void aliceResolvesInsideHerOwnTenant() {
        TenantContext.set("acme");

        UserDetails alice = userDetailsService.loadUserByUsername("alice");

        assertThat(alice.getUsername()).isEqualTo("alice");
        assertThat(alice.getAuthorities())
                .extracting(Object::toString)
                .contains("ROLE_ADMIN");
    }

    @Test
    void theSameUsernameInTwoTenantsResolvesToDifferentPeople() {
        // Both tenants have an 'ezzat'. They are not the same account: different
        // passwords, different rows, potentially different roles.
        TenantContext.set("default");
        UserDetails defaultEzzat = userDetailsService.loadUserByUsername("ezzat");

        TenantContext.set("acme");
        UserDetails acmeEzzat = userDetailsService.loadUserByUsername("ezzat");

        assertThat(defaultEzzat.getUsername()).isEqualTo(acmeEzzat.getUsername());
        assertThat(defaultEzzat.getPassword()).isNotEqualTo(acmeEzzat.getPassword());
    }

    @Test
    void rolesAreScopedPerTenantRatherThanShared() {
        // acme's ezzat is ROLE_USER there; that role object belongs to acme, not default.
        TenantContext.set("acme");
        UserDetails acmeEzzat = userDetailsService.loadUserByUsername("ezzat");

        assertThat(acmeEzzat.getAuthorities())
                .extracting(Object::toString)
                .contains("ROLE_USER")
                .doesNotContain("accounts:read:all");
    }

    @Test
    void unresolvedTenantFallsBackToDefaultRatherThanLeaking() {
        // No tenant set at all — must not silently match a user in some other tenant.
        assertThat(TenantContext.get()).isEqualTo("default");

        assertThatThrownBy(() -> userDetailsService.loadUserByUsername("alice"))
                .isInstanceOf(UsernameNotFoundException.class);
    }
}
