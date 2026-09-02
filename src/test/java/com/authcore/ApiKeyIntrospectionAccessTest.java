package com.authcore;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The introspection endpoint answers whether an arbitrary API key is still valid, so simply
 * requiring <em>some</em> credential is not enough of a guard: any caller able to authenticate
 * at all — including a low-privilege key such as the seeded demo one — would otherwise be able
 * to use it as an oracle for testing whether some other key is still good. This class exercises
 * the {@code SCOPE_apikeys:introspect} rule in {@code AuthorizationServerConfig} that closes
 * that gap.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Import(TestcontainersConfiguration.class)
class ApiKeyIntrospectionAccessTest {

    // DataSeeder's key constants are package-private to com.authcore.config; redeclared here
    // the same way MachineAccessIntegrationTest does.
    private static final String DEMO_API_KEY = "ak_demo_reporting_job_local_only_0000000000";
    private static final String GATEWAY_API_KEY = "ak_gatekeeper_introspection_local_only_00000";

    @LocalServerPort
    private int port;

    private final RestTemplate http = new RestTemplate();

    private String url(String path) {
        return "http://localhost:" + port + path;
    }

    @Test
    void refusesAnUnauthenticatedCaller() {
        assertThatThrownBy(() -> http.postForEntity(
                url("/api/internal/api-keys/introspect"), null, Map.class))
                .isInstanceOf(HttpClientErrorException.Unauthorized.class);
    }

    /**
     * The assertion that matters. Without it the rule could be plain authenticated() and this
     * class would still pass — the demo key would sail through and nothing would notice that
     * any API key at all can introspect every other one.
     */
    @Test
    void refusesAnAuthenticatedCallerLackingTheScope() {
        // The real threat model: a low-privilege key (demo, payments:read only) probing
        // whether a far more sensitive one (the gateway's own credential) is still good.
        assertThatThrownBy(() -> http.exchange(
                url("/api/internal/api-keys/introspect"), HttpMethod.POST,
                introspectionRequest(DEMO_API_KEY, GATEWAY_API_KEY), Map.class))
                .isInstanceOf(HttpClientErrorException.Forbidden.class);
    }

    /**
     * Guards against the scope check moving somewhere that runs after argument resolution —
     * a {@code @PreAuthorize} on {@code introspect} instead of the filter-chain rule, for
     * instance. {@code @RequestBody} parsing happens while Spring MVC resolves the handler
     * method's arguments, which is before a method-security interceptor around the method
     * body ever gets a chance to run. A 400 here would mean the malformed body was parsed
     * before authorization was checked at all: parser feedback handed to, and deserialization
     * work spent on, a caller never entitled to a response in the first place.
     */
    @Test
    void refusesTheCallerLackingTheScopeBeforeParsingTheBody() {
        // A 400 here would mean the body was parsed before authorization ran.
        HttpHeaders headers = new HttpHeaders();
        headers.set("X-API-Key", DEMO_API_KEY);
        headers.setContentType(MediaType.APPLICATION_JSON);

        assertThatThrownBy(() -> http.exchange(
                url("/api/internal/api-keys/introspect"), HttpMethod.POST,
                new HttpEntity<>("{ not valid json", headers), String.class))
                .isInstanceOf(HttpClientErrorException.Forbidden.class);
    }

    @Test
    @SuppressWarnings("unchecked")
    void allowsTheGatewaysKey() {
        ResponseEntity<Map> response = http.exchange(
                url("/api/internal/api-keys/introspect"), HttpMethod.POST,
                introspectionRequest(GATEWAY_API_KEY, DEMO_API_KEY), Map.class);

        assertThat(response.getStatusCode().value()).isEqualTo(200);
        assertThat(response.getBody().get("active")).isEqualTo(true);
        assertThat(response.getBody().get("name")).isEqualTo("demo-reporting-job");
        assertThat((List<String>) response.getBody().get("scopes")).containsExactly("payments:read");
    }

    private HttpEntity<Map<String, String>> introspectionRequest(String callerApiKey, String keyToIntrospect) {
        HttpHeaders headers = new HttpHeaders();
        headers.set("X-API-Key", callerApiKey);
        headers.setContentType(MediaType.APPLICATION_JSON);
        return new HttpEntity<>(Map.of("key", keyToIntrospect), headers);
    }
}
