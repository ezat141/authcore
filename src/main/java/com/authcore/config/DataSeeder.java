package com.authcore.config;

import com.authcore.user.AuthCoreUser;
import com.authcore.user.UserRepository;
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
import java.util.UUID;

@Component
public class DataSeeder implements ApplicationRunner {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final RegisteredClientRepository registeredClientRepository;

    public DataSeeder(UserRepository userRepository,
                      PasswordEncoder passwordEncoder,
                      RegisteredClientRepository registeredClientRepository) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.registeredClientRepository = registeredClientRepository;
    }

    @Override
    public void run(ApplicationArguments args) {
        seedUser();
        upsert(confidentialClient());
        upsert(publicSpaClient());
    }

    private void seedUser() {
        if (userRepository.findByUsername("ezzat").isPresent()) return;

        AuthCoreUser user = new AuthCoreUser();
        user.setUsername("ezzat");
        user.setPasswordHash(passwordEncoder.encode("password"));
        user.getAuthorities().add("ROLE_USER");
        userRepository.save(user);
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
