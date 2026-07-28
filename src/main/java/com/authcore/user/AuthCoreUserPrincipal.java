package com.authcore.user;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;

/**
 * A {@link UserDetails} that remembers which tenant the user authenticated in.
 *
 * <p>Without this, the tenant is only knowable from the request that performed the login.
 * The token request is a different request — made by the client's backend or a CLI, with
 * no subdomain, no {@code X-Tenant} header and no session — so resolving the tenant there
 * silently produced the default one and stamped every token with the wrong claim.
 *
 * <p>Carrying it on the principal ties the tenant to the authentication itself, which is
 * where it was actually established.
 */
public class AuthCoreUserPrincipal implements UserDetails {

    private final String username;
    private final String password;
    private final String tenantSlug;
    private final boolean enabled;
    private final Collection<? extends GrantedAuthority> authorities;

    public AuthCoreUserPrincipal(String username,
                                 String password,
                                 String tenantSlug,
                                 boolean enabled,
                                 Collection<? extends GrantedAuthority> authorities) {
        this.username = username;
        this.password = password;
        this.tenantSlug = tenantSlug;
        this.enabled = enabled;
        this.authorities = authorities;
    }

    public String getTenantSlug() {
        return tenantSlug;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }
}
