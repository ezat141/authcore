package com.authcore;

import com.authcore.token.RefreshTokenFamilyStore;
import com.authcore.token.ReuseDetectingOAuth2AuthorizationService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

/**
 * Reuse detection is a security control, so it gets tested against the two cases
 * that matter: the honest refresh must succeed, and the replay must burn the family.
 */
@ExtendWith(MockitoExtension.class)
class RefreshTokenReuseDetectionTest {

    private static final String LIVE_TOKEN = "live-refresh-token";
    private static final String RETIRED_TOKEN = "retired-refresh-token";
    private static final String AUTHORIZATION_ID = "auth-1";
    private static final String FAMILY_ID = "family-1";

    @Mock
    private OAuth2AuthorizationService delegate;

    @Mock
    private RefreshTokenFamilyStore familyStore;

    private ReuseDetectingOAuth2AuthorizationService service;

    @BeforeEach
    void setUp() {
        service = new ReuseDetectingOAuth2AuthorizationService(delegate, familyStore);
    }

    @Test
    void liveRefreshTokenIsPassedThroughToTheDelegate() {
        OAuth2Authorization authorization = authorization(LIVE_TOKEN);
        when(familyStore.findByTokenHash(anyString()))
                .thenReturn(Optional.of(record(false)));
        when(delegate.findByToken(LIVE_TOKEN, OAuth2TokenType.REFRESH_TOKEN))
                .thenReturn(authorization);

        OAuth2Authorization result = service.findByToken(LIVE_TOKEN, OAuth2TokenType.REFRESH_TOKEN);

        assertThat(result).isSameAs(authorization);
        verify(delegate, never()).remove(any());
        verify(familyStore, never()).deleteFamily(anyString());
    }

    @Test
    void replayingAConsumedRefreshTokenRevokesTheEntireFamily() {
        OAuth2Authorization stillLive = authorization(LIVE_TOKEN);
        when(familyStore.findByTokenHash(anyString()))
                .thenReturn(Optional.of(record(true)));
        when(familyStore.findAuthorizationIds(FAMILY_ID))
                .thenReturn(List.of(AUTHORIZATION_ID));
        when(delegate.findById(AUTHORIZATION_ID)).thenReturn(stillLive);

        OAuth2Authorization result = service.findByToken(RETIRED_TOKEN, OAuth2TokenType.REFRESH_TOKEN);

        // Null is how SAS is told to answer invalid_grant.
        assertThat(result).isNull();
        // The victim's still-valid token is destroyed too — that is the point.
        verify(delegate).remove(stillLive);
        verify(familyStore).deleteFamily(FAMILY_ID);
        verify(delegate, never()).findByToken(eq(RETIRED_TOKEN), any());
    }

    @Test
    void savingAnAuthorizationRetiresItsPreviousRefreshToken() {
        OAuth2Authorization authorization = authorization(LIVE_TOKEN);
        when(familyStore.findFamilyIdByAuthorizationId(AUTHORIZATION_ID))
                .thenReturn(Optional.of(FAMILY_ID));

        service.save(authorization);

        verify(delegate).save(authorization);
        verify(familyStore).markSupersededAsConsumed(eq(AUTHORIZATION_ID), anyString());
        verify(familyStore).record(anyString(), eq(FAMILY_ID), eq(AUTHORIZATION_ID), eq("ezzat"));
    }

    private com.authcore.token.RefreshTokenRecord record(boolean consumed) {
        return new com.authcore.token.RefreshTokenRecord(
                "hash", FAMILY_ID, AUTHORIZATION_ID, "ezzat", consumed);
    }

    private OAuth2Authorization authorization(String refreshTokenValue) {
        RegisteredClient client = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("authcore-spa")
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("http://127.0.0.1:8080/authorized")
                .scope("openid")
                .build();

        Instant now = Instant.now();
        return OAuth2Authorization.withRegisteredClient(client)
                .id(AUTHORIZATION_ID)
                .principalName("ezzat")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizedScopes(java.util.Set.of("openid"))
                .accessToken(new OAuth2AccessToken(
                        OAuth2AccessToken.TokenType.BEARER, "access", now, now.plus(5, ChronoUnit.MINUTES)))
                .refreshToken(new OAuth2RefreshToken(
                        refreshTokenValue, now, now.plus(7, ChronoUnit.DAYS)))
                .build();
    }
}
