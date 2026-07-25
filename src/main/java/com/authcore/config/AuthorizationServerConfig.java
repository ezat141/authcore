package com.authcore.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.authcore.apikey.ApiKeyAuthenticationFilter;
import com.authcore.apikey.ApiKeyAuthenticationProvider;
import com.authcore.apikey.ApiKeyStore;
import com.authcore.token.PublicRefreshTokenAuthenticationConverter;
import com.authcore.token.PublicRefreshTokenAuthenticationProvider;
import com.authcore.token.RefreshTokenFamilyStore;
import com.authcore.token.ReuseDetectingOAuth2AuthorizationService;
import com.authcore.token.RotatingRefreshTokenGenerator;
import org.springframework.context.annotation.Bean;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2AccessTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.SecurityFilterChain;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
public class AuthorizationServerConfig {

    /**
     * Resource API chain. Scoped to {@code /api/**} only, so it never sees the
     * authorization-code login redirect — the cross-chain request-cache problem that
     * forced a single chain in M1 cannot arise here.
     *
     * <p>Accepts a bearer JWT or an {@code X-API-Key}; the scope rules below are written
     * against {@code SCOPE_*} authorities, which both mechanisms produce.
     */
    @Bean
    @Order(1)
    public SecurityFilterChain resourceApiSecurityFilterChain(
            HttpSecurity http, ApiKeyStore apiKeyStore) throws Exception {
        ApiKeyAuthenticationFilter apiKeyFilter = new ApiKeyAuthenticationFilter(
                new ProviderManager(new ApiKeyAuthenticationProvider(apiKeyStore)));

        http
            .securityMatcher("/api/**")
            .authorizeHttpRequests(authorize -> authorize
                .requestMatchers(HttpMethod.GET, "/api/machine/**")
                    .hasAuthority("SCOPE_payments:read")
                .requestMatchers(HttpMethod.POST, "/api/machine/**")
                    .hasAuthority("SCOPE_payments:write")
                .anyRequest().authenticated())
            .oauth2ResourceServer(resourceServer -> resourceServer.jwt(withDefaults()))
            .addFilterBefore(apiKeyFilter, BearerTokenAuthenticationFilter.class)
            // Machine callers present a credential on every request; a session would
            // only add server state and CSRF exposure for nothing.
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .csrf(AbstractHttpConfigurer::disable);

        return http.build();
    }

    @Bean
    public ApiKeyStore apiKeyStore(JdbcOperations jdbc) {
        return new ApiKeyStore(jdbc);
    }

    @Bean
    @Order(2)
    public SecurityFilterChain securityFilterChain(
            HttpSecurity http,
            RegisteredClientRepository registeredClientRepository) throws Exception {
        http
            .with(new OAuth2AuthorizationServerConfigurer(), configurer -> configurer
                .oidc(withDefaults())
                // Teach the token endpoint how to authenticate a public client on the
                // refresh grant — needed because we issue public clients refresh tokens.
                .clientAuthentication(clientAuth -> clientAuth
                    .authenticationConverter(new PublicRefreshTokenAuthenticationConverter())
                    .authenticationProvider(new PublicRefreshTokenAuthenticationProvider(
                            registeredClientRepository))))
            .authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/actuator/**").permitAll()
                .anyRequest().authenticated())
            .formLogin(withDefaults());

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    // M2: clients stored in oauth2_registered_client table.
    @Bean
    public RegisteredClientRepository registeredClientRepository(JdbcOperations jdbc) {
        return new JdbcRegisteredClientRepository(jdbc);
    }

    @Bean
    public RefreshTokenFamilyStore refreshTokenFamilyStore(JdbcOperations jdbc) {
        return new RefreshTokenFamilyStore(jdbc);
    }

    // M2: auth codes, access tokens, refresh tokens survive server restarts.
    // M3: wrapped so a replayed refresh token revokes its whole rotation family.
    @Bean
    public OAuth2AuthorizationService authorizationService(
            JdbcOperations jdbc,
            RegisteredClientRepository registeredClientRepository,
            RefreshTokenFamilyStore refreshTokenFamilyStore) {
        return new ReuseDetectingOAuth2AuthorizationService(
                new JdbcOAuth2AuthorizationService(jdbc, registeredClientRepository),
                refreshTokenFamilyStore);
    }

    // M2: consent decisions survive server restarts — no re-consent on every login.
    @Bean
    public OAuth2AuthorizationConsentService authorizationConsentService(
            JdbcOperations jdbc,
            RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationConsentService(jdbc, registeredClientRepository);
    }

    // M7 replaces this with JpaJwkSource + key rotation from DB.
    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        KeyPair keyPair = generateRsaKey();
        RSAKey rsaKey = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
            .privateKey((RSAPrivateKey) keyPair.getPrivate())
            .keyID(UUID.randomUUID().toString())
            .build();
        return new ImmutableJWKSet<>(new JWKSet(rsaKey));
    }

    private static KeyPair generateRsaKey() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            return generator.generateKeyPair();
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException(ex);
        }
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    /**
     * Mirrors the generator SAS builds by default, but swaps in
     * {@link RotatingRefreshTokenGenerator} so public clients get refresh tokens too.
     */
    @Bean
    public OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator(JWKSource<SecurityContext> jwkSource) {
        return new DelegatingOAuth2TokenGenerator(
                new JwtGenerator(new NimbusJwtEncoder(jwkSource)),
                new OAuth2AccessTokenGenerator(),
                new RotatingRefreshTokenGenerator());
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
            .issuer("http://localhost:8080")
            .build();
    }
}
