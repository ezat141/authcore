package com.authcore;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Import;
import org.springframework.http.*;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The M7 acceptance criterion, driven through the real endpoints: revoke a token and it
 * stops working straight away, rather than lingering until it expires.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Import(TestcontainersConfiguration.class)
class RevocationEndToEndTest {

    @LocalServerPort
    private int port;

    private final RestTemplate http = new RestTemplate();

    private String url(String path) {
        return "http://localhost:" + port + path;
    }

    @Test
    @SuppressWarnings("unchecked")
    void aRevokedAccessTokenIsRejectedImmediately() {
        String accessToken = machineToken();

        // Works before revocation.
        assertThat(callApi(accessToken).getStatusCode().value()).isEqualTo(200);

        revoke(accessToken);

        // And is refused straight after, without waiting for it to expire.
        assertThatThrownBy(() -> callApi(accessToken))
                .isInstanceOf(HttpClientErrorException.Unauthorized.class);
    }

    @Test
    @SuppressWarnings("unchecked")
    void revokingOneTokenDoesNotAffectAnother() {
        String doomed = machineToken();
        String survivor = machineToken();

        revoke(doomed);

        assertThatThrownBy(() -> callApi(doomed))
                .isInstanceOf(HttpClientErrorException.Unauthorized.class);
        assertThat(callApi(survivor).getStatusCode().value()).isEqualTo(200);
    }

    @Test
    void revokingAnUnknownTokenStillReturnsSuccess() {
        // RFC 7009 §2.2: the endpoint must not reveal whether a token existed.
        ResponseEntity<String> response = revoke("not-a-real-token");

        assertThat(response.getStatusCode().value()).isEqualTo(200);
    }

    @SuppressWarnings("unchecked")
    private String machineToken() {
        HttpHeaders headers = new HttpHeaders();
        headers.setBasicAuth("authcore-machine", "machine-secret");
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "client_credentials");
        form.add("scope", "payments:read");

        Map<String, Object> body = http
                .postForEntity(url("/oauth2/token"), new HttpEntity<>(form, headers), Map.class)
                .getBody();
        return (String) body.get("access_token");
    }

    private ResponseEntity<String> revoke(String token) {
        HttpHeaders headers = new HttpHeaders();
        headers.setBasicAuth("authcore-machine", "machine-secret");
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("token", token);
        form.add("token_type_hint", "access_token");

        return http.postForEntity(url("/oauth2/revoke"), new HttpEntity<>(form, headers), String.class);
    }

    @SuppressWarnings("rawtypes")
    private ResponseEntity<Map> callApi(String accessToken) {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken);
        return http.exchange(url("/api/machine/payments"), HttpMethod.GET,
                new HttpEntity<>(headers), Map.class);
    }
}
