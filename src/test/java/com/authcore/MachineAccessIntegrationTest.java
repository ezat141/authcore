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
 * Covers both machine-to-machine paths against a real server: the client-credentials
 * grant, and the API-key header. The scope rules are shared, so each mechanism is
 * checked for both a granted and a missing scope.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Import(TestcontainersConfiguration.class)
class MachineAccessIntegrationTest {

    private static final String DEMO_API_KEY = "ak_demo_reporting_job_local_only_0000000000";

    @LocalServerPort
    private int port;

    private final RestTemplate http = new RestTemplate();

    private String url(String path) {
        return "http://localhost:" + port + path;
    }

    // ---------- client_credentials ----------

    @Test
    @SuppressWarnings("unchecked")
    void clientCredentialsGrantReturnsAScopedToken() {
        Map<String, Object> token = requestClientCredentialsToken("payments:read payments:write");

        assertThat(token).containsKey("access_token");
        assertThat(token.get("token_type")).isEqualTo("Bearer");
        assertThat((String) token.get("scope"))
                .contains("payments:read")
                .contains("payments:write");
        // No user is involved, so there is nothing to refresh against.
        assertThat(token).doesNotContainKey("refresh_token");
    }

    @Test
    @SuppressWarnings("unchecked")
    void clientCredentialsTokenCanCallTheResourceApi() {
        String accessToken = (String) requestClientCredentialsToken("payments:read").get("access_token");

        ResponseEntity<Map> response = http.exchange(
                url("/api/machine/payments"), HttpMethod.GET,
                new HttpEntity<>(bearer(accessToken)), Map.class);

        assertThat(response.getStatusCode().value()).isEqualTo(200);
        assertThat(response.getBody().get("authenticatedVia")).isEqualTo("bearer-jwt");
        assertThat(response.getBody().get("caller")).isEqualTo("authcore-machine");
    }

    @Test
    @SuppressWarnings("unchecked")
    void tokenWithoutWriteScopeIsForbiddenOnWriteEndpoint() {
        String readOnlyToken = (String) requestClientCredentialsToken("payments:read").get("access_token");

        assertThatThrownBy(() -> http.exchange(
                url("/api/machine/payments"), HttpMethod.POST,
                new HttpEntity<>(bearer(readOnlyToken)), Map.class))
                .isInstanceOf(HttpClientErrorException.Forbidden.class);
    }

    // ---------- API key ----------

    @Test
    @SuppressWarnings("unchecked")
    void apiKeyAuthenticatesAndIsScopeChecked() {
        HttpHeaders headers = new HttpHeaders();
        headers.set("X-API-Key", DEMO_API_KEY);

        ResponseEntity<Map> response = http.exchange(
                url("/api/machine/payments"), HttpMethod.GET,
                new HttpEntity<>(headers), Map.class);

        assertThat(response.getStatusCode().value()).isEqualTo(200);
        assertThat(response.getBody().get("authenticatedVia")).isEqualTo("api-key");
        assertThat(response.getBody().get("caller")).isEqualTo("demo-reporting-job");
    }

    @Test
    void apiKeyWithoutWriteScopeIsForbiddenOnWriteEndpoint() {
        HttpHeaders headers = new HttpHeaders();
        headers.set("X-API-Key", DEMO_API_KEY);

        // The demo key holds payments:read only.
        assertThatThrownBy(() -> http.exchange(
                url("/api/machine/payments"), HttpMethod.POST,
                new HttpEntity<>(headers), Map.class))
                .isInstanceOf(HttpClientErrorException.Forbidden.class);
    }

    @Test
    void unknownApiKeyIsRejected() {
        HttpHeaders headers = new HttpHeaders();
        headers.set("X-API-Key", "ak_not_a_real_key");

        assertThatThrownBy(() -> http.exchange(
                url("/api/machine/payments"), HttpMethod.GET,
                new HttpEntity<>(headers), Map.class))
                .isInstanceOf(HttpClientErrorException.Unauthorized.class);
    }

    @Test
    void resourceApiRejectsAnUnauthenticatedCall() {
        assertThatThrownBy(() -> http.getForEntity(url("/api/machine/payments"), Map.class))
                .isInstanceOf(HttpClientErrorException.class);
    }

    // ---------- helpers ----------

    @SuppressWarnings("unchecked")
    private Map<String, Object> requestClientCredentialsToken(String scope) {
        HttpHeaders headers = new HttpHeaders();
        headers.setBasicAuth("authcore-machine", "machine-secret");
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "client_credentials");
        form.add("scope", scope);

        return http.postForEntity(url("/oauth2/token"), new HttpEntity<>(form, headers), Map.class).getBody();
    }

    private HttpHeaders bearer(String accessToken) {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken);
        return headers;
    }
}
