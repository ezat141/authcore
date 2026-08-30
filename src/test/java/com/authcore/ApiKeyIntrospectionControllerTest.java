package com.authcore;

import com.authcore.apikey.ApiKeyIntrospectionController;
import com.authcore.apikey.ApiKeyIntrospectionRequest;
import com.authcore.apikey.ApiKeyIntrospectionResponse;
import com.authcore.apikey.ApiKeyStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class ApiKeyIntrospectionControllerTest {

    ApiKeyStore store;
    ApiKeyIntrospectionController controller;

    @BeforeEach
    void setUp() {
        store = mock(ApiKeyStore.class);
        controller = new ApiKeyIntrospectionController(store);
    }

    @Test
    void reportsAUsableKeyAsActiveWithItsScopes() {
        Instant expiry = Instant.now().plus(Duration.ofDays(30));
        when(store.findByRawKey("ak_good")).thenReturn(java.util.Optional.of(
                new com.authcore.apikey.ApiKey("id-1", "reporting", "ak_good", Set.of("payments:read"), true, expiry)));

        ApiKeyIntrospectionResponse response =
                controller.introspect(new ApiKeyIntrospectionRequest("ak_good"));

        assertThat(response.active()).isTrue();
        assertThat(response.name()).isEqualTo("reporting");
        assertThat(response.scopes()).containsExactly("payments:read");
        assertThat(response.expiresAt()).isEqualTo(expiry);
    }

    @Test
    void reportsAnUnknownKeyAsInactiveAndSaysNothingElse() {
        when(store.findByRawKey(anyString())).thenReturn(java.util.Optional.empty());

        ApiKeyIntrospectionResponse response =
                controller.introspect(new ApiKeyIntrospectionRequest("ak_nope"));

        assertThat(response.active()).isFalse();
        assertThat(response.name()).isNull();
        assertThat(response.scopes()).isNull();
    }

    /**
     * A disabled key and an unknown key must be indistinguishable to the caller, or this
     * endpoint becomes a way to confirm which keys exist.
     */
    @Test
    void reportsADisabledKeyIdenticallyToAnUnknownOne() {
        when(store.findByRawKey("ak_disabled")).thenReturn(java.util.Optional.of(
                new com.authcore.apikey.ApiKey("id-2", "old", "ak_disabled", Set.of("payments:read"), false, null)));

        assertThat(controller.introspect(new ApiKeyIntrospectionRequest("ak_disabled")))
                .isEqualTo(ApiKeyIntrospectionResponse.inactive());
    }

    @Test
    void reportsAnExpiredKeyIdenticallyToAnUnknownOne() {
        when(store.findByRawKey("ak_expired")).thenReturn(java.util.Optional.of(
                new com.authcore.apikey.ApiKey("id-3", "lapsed", "ak_expired", Set.of("payments:read"),
                        true, Instant.now().minus(Duration.ofDays(1)))));

        assertThat(controller.introspect(new ApiKeyIntrospectionRequest("ak_expired")))
                .isEqualTo(ApiKeyIntrospectionResponse.inactive());
    }

    @Test
    void doesNotTouchLastUsedForAKeyItRefuses() {
        when(store.findByRawKey(anyString())).thenReturn(java.util.Optional.empty());

        controller.introspect(new ApiKeyIntrospectionRequest("ak_nope"));

        verify(store, never()).touchLastUsed(anyString());
    }

    @Test
    void treatsABlankKeyAsInactiveWithoutQueryingTheStore() {
        assertThat(controller.introspect(new ApiKeyIntrospectionRequest("  ")))
                .isEqualTo(ApiKeyIntrospectionResponse.inactive());
        verify(store, never()).findByRawKey(anyString());
    }
}
