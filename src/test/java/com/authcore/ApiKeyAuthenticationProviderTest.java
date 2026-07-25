package com.authcore;

import com.authcore.apikey.ApiKey;
import com.authcore.apikey.ApiKeyAuthenticationProvider;
import com.authcore.apikey.ApiKeyAuthenticationToken;
import com.authcore.apikey.ApiKeyStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.core.Authentication;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class ApiKeyAuthenticationProviderTest {

    private static final String RAW_KEY = "ak_test_key";

    @Mock
    private ApiKeyStore apiKeyStore;

    private ApiKeyAuthenticationProvider provider;

    @BeforeEach
    void setUp() {
        provider = new ApiKeyAuthenticationProvider(apiKeyStore);
    }

    @Test
    void validKeyIsAuthenticatedAndScopesBecomeScopeAuthorities() {
        when(apiKeyStore.findByRawKey(RAW_KEY))
                .thenReturn(Optional.of(key(true, null, Set.of("payments:read", "payments:write"))));

        Authentication result = provider.authenticate(new ApiKeyAuthenticationToken(RAW_KEY));

        assertThat(result.isAuthenticated()).isTrue();
        assertThat(result.getName()).isEqualTo("reporting-job");
        // Same shape a JWT scope claim produces, so one rule guards both paths.
        assertThat(result.getAuthorities())
                .extracting(Object::toString)
                .containsExactlyInAnyOrder("SCOPE_payments:read", "SCOPE_payments:write");
        verify(apiKeyStore).touchLastUsed("key-1");
    }

    @Test
    void unknownKeyIsRejected() {
        when(apiKeyStore.findByRawKey(anyString())).thenReturn(Optional.empty());

        assertThatThrownBy(() -> provider.authenticate(new ApiKeyAuthenticationToken("nope")))
                .isInstanceOf(BadCredentialsException.class);
        verify(apiKeyStore, never()).touchLastUsed(anyString());
    }

    @Test
    void disabledKeyIsRejected() {
        when(apiKeyStore.findByRawKey(RAW_KEY))
                .thenReturn(Optional.of(key(false, null, Set.of("payments:read"))));

        assertThatThrownBy(() -> provider.authenticate(new ApiKeyAuthenticationToken(RAW_KEY)))
                .isInstanceOf(DisabledException.class);
        verify(apiKeyStore, never()).touchLastUsed(anyString());
    }

    @Test
    void expiredKeyIsRejected() {
        Instant yesterday = Instant.now().minus(1, ChronoUnit.DAYS);
        when(apiKeyStore.findByRawKey(RAW_KEY))
                .thenReturn(Optional.of(key(true, yesterday, Set.of("payments:read"))));

        assertThatThrownBy(() -> provider.authenticate(new ApiKeyAuthenticationToken(RAW_KEY)))
                .isInstanceOf(CredentialsExpiredException.class);
        verify(apiKeyStore, never()).touchLastUsed(anyString());
    }

    private ApiKey key(boolean enabled, Instant expiresAt, Set<String> scopes) {
        return new ApiKey("key-1", "reporting-job", "ak_test", scopes, enabled, expiresAt);
    }
}
