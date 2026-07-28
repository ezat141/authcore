package com.authcore.config;

import com.authcore.apikey.ApiKeyStore;
import com.authcore.tenant.Tenant;
import com.authcore.tenant.TenantRepository;
import com.authcore.user.AuthCoreUser;
import com.authcore.user.Permission;
import com.authcore.user.PermissionRepository;
import com.authcore.user.Role;
import com.authcore.user.RoleRepository;
import com.authcore.user.UserRepository;
import org.springframework.transaction.annotation.Transactional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.util.Set;
import java.util.UUID;

@Component
public class DataSeeder implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(DataSeeder.class);

    static final String DEMO_API_KEY_NAME = "demo-reporting-job";
    static final String DEMO_API_KEY = "ak_demo_reporting_job_local_only_0000000000";

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PermissionRepository permissionRepository;
    private final TenantRepository tenantRepository;
    private final PasswordEncoder passwordEncoder;
    private final RegisteredClientRepository registeredClientRepository;
    private final ApiKeyStore apiKeyStore;

    public DataSeeder(UserRepository userRepository,
                      RoleRepository roleRepository,
                      PermissionRepository permissionRepository,
                      TenantRepository tenantRepository,
                      PasswordEncoder passwordEncoder,
                      RegisteredClientRepository registeredClientRepository,
                      ApiKeyStore apiKeyStore) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.permissionRepository = permissionRepository;
        this.tenantRepository = tenantRepository;
        this.passwordEncoder = passwordEncoder;
        this.registeredClientRepository = registeredClientRepository;
        this.apiKeyStore = apiKeyStore;
    }

    @Override
    @Transactional
    public void run(ApplicationArguments args) {
        Tenant defaultTenant = requireTenant("default");
        Tenant acme = requireTenant("acme");

        seedTenantRoles(defaultTenant);
        seedTenantRoles(acme);

        seedUser(defaultTenant, "ezzat", "password", "ROLE_USER");
        seedUser(defaultTenant, "admin", "admin-password", "ROLE_ADMIN");

        // Same usernames, different tenant — the composite key makes these distinct
        // people, and each can only authenticate against their own tenant.
        seedUser(acme, "ezzat", "acme-password", "ROLE_USER");
        seedUser(acme, "alice", "alice-password", "ROLE_ADMIN");

        upsert(confidentialClient());
        upsert(publicSpaClient());
        upsert(machineClient());
        seedApiKey();
    }

    private Tenant requireTenant(String slug) {
        return tenantRepository.findBySlug(slug)
                .orElseThrow(() -> new IllegalStateException("Tenant not created by migration: " + slug));
    }

    /**
     * Every tenant gets its own role objects. Permissions are shared — they are a
     * vocabulary of capabilities, not policy — but which roles exist and what they grant
     * is each tenant's own business.
     */
    private void seedTenantRoles(Tenant tenant) {
        Permission paymentsRead    = permission("payments:read",      "Read payment records");
        Permission paymentsWrite   = permission("payments:write",     "Create and modify payments");
        Permission accountsRead    = permission("accounts:read",      "Read own account");
        Permission accountsReadAll = permission("accounts:read:all",  "Read any account, regardless of owner");
        Permission keysRead        = permission("keys:read",          "Inspect signing keys");
        Permission keysRotate      = permission("keys:rotate",        "Rotate the active signing key");

        Role user = role(tenant, "ROLE_USER", "Standard end user");
        addPermissions(user, paymentsRead, accountsRead);

        Role admin = role(tenant, "ROLE_ADMIN", "Administrator");
        addPermissions(admin, paymentsRead, paymentsWrite, accountsRead, accountsReadAll, keysRead, keysRotate);
    }

    private Permission permission(String name, String description) {
        return permissionRepository.findByName(name)
                .orElseGet(() -> permissionRepository.save(new Permission(name, description)));
    }

    private Role role(Tenant tenant, String name, String description) {
        return roleRepository.findByTenantSlugAndName(tenant.getSlug(), name)
                .orElseGet(() -> roleRepository.save(new Role(name, description, tenant)));
    }

    private void addPermissions(Role role, Permission... permissions) {
        boolean changed = role.getPermissions().addAll(Set.of(permissions));
        if (changed) {
            roleRepository.save(role);
        }
    }

    private void seedUser(Tenant tenant, String username, String rawPassword, String roleName) {
        if (userRepository.findByTenantSlugAndUsername(tenant.getSlug(), username).isPresent()) return;

        Role role = roleRepository.findByTenantSlugAndName(tenant.getSlug(), roleName)
                .orElseThrow(() -> new IllegalStateException(
                        "Role " + roleName + " not seeded for tenant " + tenant.getSlug()));

        AuthCoreUser user = new AuthCoreUser();
        user.setTenant(tenant);
        user.setUsername(username);
        user.setPasswordHash(passwordEncoder.encode(rawPassword));
        user.getRoles().add(role);
        userRepository.save(user);
    }

    /**
     * Machine-to-machine client: no user involved, so no authorization code, no consent,
     * and no refresh token (it can just ask for another token with its own credentials).
     */
    private RegisteredClient machineClient() {
        return RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("authcore-machine")
                .clientSecret(passwordEncoder.encode("machine-secret"))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .scope("payments:read")
                .scope("payments:write")
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(10))
                        .build())
                .build();
    }

    /**
     * Demo key with a fixed value so the flow is reproducible without a provisioning API.
     * Real keys are generated by {@link ApiKeyStore#generateKey()} and shown once at
     * creation — this seeded one exists only for local demos.
     */
    private void seedApiKey() {
        if (apiKeyStore.existsByName(DEMO_API_KEY_NAME)) return;

        apiKeyStore.save(
                DEMO_API_KEY_NAME,
                DEMO_API_KEY,
                Set.of("payments:read"),
                Instant.now().plus(Duration.ofDays(365)));

        log.warn("Seeded demo API key '{}' with scope payments:read. Local development only.",
                DEMO_API_KEY_NAME);
    }

    /** Server-side client: authenticates with a secret, so PKCE stays optional. */
    private RegisteredClient confidentialClient() {
        return RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("authcore-client")
                .clientSecret(passwordEncoder.encode("secret"))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("http://127.0.0.1:8080/authorized")
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .scope("payments:read")
                .scope("payments:write")
                .clientSettings(ClientSettings.builder()
                        .requireAuthorizationConsent(true)
                        .build())
                .tokenSettings(rotatingTokens())
                .build();
    }

    /**
     * Browser/mobile client: ships to the user's device, so it cannot hold a secret.
     * PKCE is mandatory here — it is the only thing binding the authorization code
     * to the client that requested it.
     */
    private RegisteredClient publicSpaClient() {
        return RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("authcore-spa")
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("http://127.0.0.1:8080/authorized")
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .scope("payments:read")
                .clientSettings(ClientSettings.builder()
                        .requireProofKey(true)
                        .requireAuthorizationConsent(true)
                        .build())
                .tokenSettings(rotatingTokens())
                .build();
    }

    /** Rotation is what gives reuse detection something to detect. */
    private TokenSettings rotatingTokens() {
        return TokenSettings.builder()
                .reuseRefreshTokens(false)
                .accessTokenTimeToLive(Duration.ofMinutes(5))
                .refreshTokenTimeToLive(Duration.ofDays(7))
                .build();
    }

    /** Re-seeds on every boot so settings changes take effect without a manual DB wipe. */
    private void upsert(RegisteredClient client) {
        RegisteredClient existing = registeredClientRepository.findByClientId(client.getClientId());
        if (existing != null) {
            client = RegisteredClient.from(client).id(existing.getId()).build();
        }
        registeredClientRepository.save(client);
    }
}
