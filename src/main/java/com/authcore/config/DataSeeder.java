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
import org.springframework.stereotype.Component;

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
        seedClient();
    }

    private void seedUser() {
        if (userRepository.findByUsername("ezzat").isPresent()) return;

        AuthCoreUser user = new AuthCoreUser();
        user.setUsername("ezzat");
        user.setPasswordHash(passwordEncoder.encode("password"));
        user.getAuthorities().add("ROLE_USER");
        userRepository.save(user);
    }

    private void seedClient() {
        if (registeredClientRepository.findByClientId("authcore-client") != null) return;

        RegisteredClient client = RegisteredClient.withId(UUID.randomUUID().toString())
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
                .build();
        registeredClientRepository.save(client);
    }
}
