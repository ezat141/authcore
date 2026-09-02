package com.authcore;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowableOfType;

/**
 * A body {@code ApiKeyIntrospectionController} cannot parse must come back as a 400, even
 * though the caller is authenticated and holds the scope this endpoint requires.
 *
 * <p>This only reproduces against a real server. Unhandled, the controller's {@code
 * HttpMessageNotReadableException} makes the embedded container's error-page mechanism
 * forward the request to {@code /error} before the response is sent. That forwarded request
 * no longer matches chain 1's {@code securityMatcher("/api/**")} in {@code
 * AuthorizationServerConfig}, so it falls through to chain 2, which has no filter that
 * recognizes {@code X-API-Key}. What comes back there is content-negotiated on the forwarded
 * request's {@code Accept} header, not one fixed answer: {@code application/json}, a bare
 * wildcard, or no {@code Accept} header at all gets a 401 with a {@code WWW-Authenticate:
 * Bearer resource_metadata="..."} challenge, while an {@code Accept} containing any {@code
 * text/*} type gets a 302 redirect to the login page instead. Either way, a machine caller
 * like GateKeeper gets something other than the clean 400 it should.
 *
 * <p>This test exercises the 302 path specifically. {@link RestTemplate}, given no explicit
 * {@code Accept} header, computes one itself from its registered converters for a {@code
 * String.class} response, and that computed default includes {@code text/plain} - enough to
 * land in the {@code text/*} bucket above. Do not "simplify" this to a {@code MockMvc} test:
 * a mock-environment {@code MockMvc} test exercises neither path, since without a real
 * container there is no error page forward to mis-route in the first place, silently losing
 * this coverage. {@link LocalServerPort} plus a real HTTP client, as in {@link
 * MachineAccessIntegrationTest}, stays required.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Import(TestcontainersConfiguration.class)
class ApiKeyIntrospectionMalformedBodyTest {

    // DataSeeder.GATEWAY_API_KEY is package-private to com.authcore.config; redeclared here
    // the same way MachineAccessIntegrationTest does. Must be a key actually scoped for this
    // endpoint (SCOPE_apikeys:introspect, guarded since Task 3) - the demo key no longer
    // clears authorization, so it would never reach the malformed-body handling under test.
    private static final String GATEWAY_API_KEY = "ak_gatekeeper_introspection_local_only_00000";

    @LocalServerPort
    private int port;

    private final RestTemplate http = new RestTemplate();

    private String url(String path) {
        return "http://localhost:" + port + path;
    }

    @Test
    void malformedJsonIsABadRequestNotAnAuthenticationFailure() {
        assertBadRequestNotAuthFailure("{ not valid json");
    }

    @Test
    void emptyBodyIsABadRequestNotAnAuthenticationFailure() {
        assertBadRequestNotAuthFailure("");
    }

    @Test
    void literalJsonNullIsABadRequestNotAnAuthenticationFailure() {
        assertBadRequestNotAuthFailure("null");
    }

    private void assertBadRequestNotAuthFailure(String rawBody) {
        HttpHeaders headers = new HttpHeaders();
        headers.set("X-API-Key", GATEWAY_API_KEY);
        headers.setContentType(MediaType.APPLICATION_JSON);

        HttpClientErrorException.BadRequest ex = catchThrowableOfType(
                () -> http.exchange(
                        url("/api/internal/api-keys/introspect"), HttpMethod.POST,
                        new HttpEntity<>(rawBody, headers), String.class),
                HttpClientErrorException.BadRequest.class);

        assertThat(ex).as("expected a clean 400, not a redirect to the login page").isNotNull();
        assertThat(ex.getResponseHeaders().getLocation()).isNull();
        assertThat(ex.getResponseHeaders().get("WWW-Authenticate")).isNull();
    }
}
