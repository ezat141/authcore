package com.authcore.config;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.authcore.apikey.ApiKeyAuthenticationFilter;
import com.authcore.apikey.ApiKeyAuthenticationProvider;
import com.authcore.apikey.ApiKeyStore;
import com.authcore.keys.JpaJwkSource;
import com.authcore.keys.KeyCipher;
import com.authcore.keys.SigningKeyService;
import org.springframework.beans.factory.annotation.Value;
import com.authcore.security.AuthCoreJwtAuthoritiesConverter;
import com.authcore.tenant.TenantAuthorizationManager;
import com.authcore.tenant.TenantResolutionFilter;
import com.authcore.tenant.TenantService;
import com.authcore.token.AuthCoreTokenCustomizer;
import org.springframework.security.authorization.AuthenticatedAuthorizationManager;
import org.springframework.security.authorization.AuthorityAuthorizationManager;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import com.authcore.user.AuthCoreJacksonModules;
import com.authcore.user.UserRepository;
import tools.jackson.databind.json.JsonMapper;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
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

import java.util.UUID;

import java.util.List;

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
            HttpSecurity http, ApiKeyStore apiKeyStore, TenantService tenantService) throws Exception {
        ApiKeyAuthenticationFilter apiKeyFilter = new ApiKeyAuthenticationFilter(
                new ProviderManager(new ApiKeyAuthenticationProvider(apiKeyStore)));

        http
            .securityMatcher("/api/**")
            .authorizeHttpRequests(authorize -> authorize
                .requestMatchers(HttpMethod.GET, "/api/machine/**")
                    .access(tenantScoped(AuthorityAuthorizationManager.hasAuthority("SCOPE_payments:read")))
                .requestMatchers(HttpMethod.POST, "/api/machine/**")
                    .access(tenantScoped(AuthorityAuthorizationManager.hasAuthority("SCOPE_payments:write")))
                .anyRequest()
                    .access(tenantScoped(AuthenticatedAuthorizationManager.authenticated())))
            .oauth2ResourceServer(resourceServer -> resourceServer
                .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter())))
            .addFilterBefore(apiKeyFilter, BearerTokenAuthenticationFilter.class)
            // Tenant must be known before anything authenticates or authorizes.
            .addFilterBefore(new TenantResolutionFilter(tenantService), ApiKeyAuthenticationFilter.class)
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

    /** Wraps a rule so a token from another tenant is refused even when the rule passes. */
    private static AuthorizationManager<RequestAuthorizationContext> tenantScoped(
            AuthorizationManager<RequestAuthorizationContext> delegate) {
        return new TenantAuthorizationManager(delegate);
    }

    /** Reads roles and permissions out of the JWT, not just scope. */
    private static JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(new AuthCoreJwtAuthoritiesConverter());
        return converter;
    }

    @Bean
    @Order(2)
    public SecurityFilterChain securityFilterChain(
            HttpSecurity http,
            RegisteredClientRepository registeredClientRepository,
            TenantService tenantService) throws Exception {
        http
            // Runs before authentication so /oauth2/authorize and the /login POST both
            // resolve the same tenant — the login form itself carries no tenant hint.
            .addFilterBefore(new TenantResolutionFilter(tenantService),
                    UsernamePasswordAuthenticationFilter.class)
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
                // The redirect target must be reachable without a session: the browser
                // arrives here on 127.0.0.1 while the login happened on localhost, and
                // no cookie crosses between them.
                .requestMatchers("/authorized").permitAll()
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
                jdbcAuthorizationService(jdbc, registeredClientRepository),
                refreshTokenFamilyStore);
    }

    /**
     * The stock service with one change: an {@code ObjectMapper} that can read our custom
     * principal back out of the {@code attributes} column.
     */
    private static JdbcOAuth2AuthorizationService jdbcAuthorizationService(
            JdbcOperations jdbc, RegisteredClientRepository registeredClientRepository) {
        JdbcOAuth2AuthorizationService service =
                new JdbcOAuth2AuthorizationService(jdbc, registeredClientRepository);
        JsonMapper jsonMapper = AuthCoreJacksonModules.authorizationJsonMapper();

        service.setAuthorizationRowMapper(
                new JdbcOAuth2AuthorizationService.JsonMapperOAuth2AuthorizationRowMapper(
                        registeredClientRepository, jsonMapper));
        service.setAuthorizationParametersMapper(
                new JdbcOAuth2AuthorizationService.JsonMapperOAuth2AuthorizationParametersMapper(jsonMapper));

        return service;
    }

    // M2: consent decisions survive server restarts — no re-consent on every login.
    @Bean
    public OAuth2AuthorizationConsentService authorizationConsentService(
            JdbcOperations jdbc,
            RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationConsentService(jdbc, registeredClientRepository);
    }

    /**
     * Master key for encrypting signing keys at rest.
     *
     * <p>Defaulted so the project starts with no setup. That default is a published
     * constant and therefore no secret at all — any real deployment must override
     * {@code authcore.keys.master-key}, and better still keep the material in a KMS.
     */
    @Bean
    public KeyCipher keyCipher(
            @Value("${authcore.keys.master-key:YXV0aGNvcmUtZGV2LW9ubHktbWFzdGVyLWtleS0zMmI=}")
            String masterKey) {
        return new KeyCipher(masterKey);
    }

    // M7: keys live in the database, so a restart no longer invalidates every token.
    @Bean
    public JpaJwkSource jwkSource(SigningKeyService signingKeyService) {
        signingKeyService.initialize();
        return new JpaJwkSource(signingKeyService);
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
    public OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator(
            JWKSource<SecurityContext> jwkSource, UserRepository userRepository) {
        NimbusJwtEncoder jwtEncoder = new NimbusJwtEncoder(jwkSource);
        // While a rotation is in flight both the active and the retiring key match the
        // encoder's query, and its default response to an ambiguous match is to refuse to
        // sign at all — which would take the token endpoint down for the length of the
        // overlap. JpaJwkSource guarantees the active key is first, so first is correct.
        jwtEncoder.setJwkSelector(List::getFirst);

        JwtGenerator jwtGenerator = new JwtGenerator(jwtEncoder);
        // SAS only auto-applies an OAuth2TokenCustomizer bean to the generator it builds
        // itself. We supply our own generator, so the customizer must be set here or the
        // roles/permissions claims silently never appear.
        jwtGenerator.setJwtCustomizer(new AuthCoreTokenCustomizer(userRepository));

        return new DelegatingOAuth2TokenGenerator(
                jwtGenerator,
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
