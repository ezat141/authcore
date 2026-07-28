package com.authcore.user;

import com.authcore.tenant.TenantContext;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.stream.Collectors;

@Service
public class AuthCoreUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    public AuthCoreUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    /**
     * Resolves the user <em>within the current tenant only</em>.
     *
     * <p>This is the single point where cross-tenant authentication is prevented: a user
     * who exists in another tenant is simply not found here, so their password is never
     * even compared. The tenant comes from {@link TenantContext} because the
     * {@link UserDetailsService} contract offers nowhere else to put it.
     *
     * <p>The error message deliberately names the tenant. It is logged, not returned to
     * the caller — Spring turns any failure here into the same generic bad-credentials
     * response, so this cannot be used to probe which tenants a username exists in.
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        String tenant = TenantContext.get();

        return userRepository.findByTenantSlugAndUsername(tenant, username)
                .map(user -> (UserDetails) new AuthCoreUserPrincipal(
                        user.getUsername(),
                        user.getPasswordHash(),
                        // Pinned here so later requests do not have to re-derive it.
                        user.getTenantSlug(),
                        user.isEnabled(),
                        // Roles and their permissions both become authorities, so
                        // hasRole('USER') and hasAuthority('payments:write') both work.
                        user.toAuthorityNames().stream()
                                .map(SimpleGrantedAuthority::new)
                                .collect(Collectors.toSet())))
                .orElseThrow(() -> new UsernameNotFoundException(
                        "User '" + username + "' not found in tenant '" + tenant + "'"));
    }
}
