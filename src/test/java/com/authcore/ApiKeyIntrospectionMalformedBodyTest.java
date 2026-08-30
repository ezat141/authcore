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
 * though the caller authenticated fine.
 *
 * <p>This only reproduces against a real server. Unhandled, the controller's {@code
 * HttpMessageNotReadableException} makes the embedded container's error-page mechanism
 * forward the request to {@code /error} before the response is sent. That forwarded request
 * no longer matches chain 1's {@code securityMatcher("/api/**")} in {@code
 * AuthorizationServerConfig}, so it falls through to chain 2, which has no filter that
 * recognizes {@code X-API-Key} - only {@code formLogin()} - and comes back a 302 redirect to
 * the login page instead. A machine caller like GateKeeper gets an HTML login page where it
 * expected a JSON answer, with no clean way to tell that apart from its own credential being
 * refused. A mock-environment {@code MockMvc} test does not exercise this: without a real
 * container there is no error page forward to mis-route, so {@link LocalServerPort} plus a
 * real HTTP client, as in {@link MachineAccessIntegrationTest}, is required.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Import(TestcontainersConfiguration.class)
class ApiKeyIntrospectionMalformedBodyTest {

    // DataSeeder.DEMO_API_KEY is package-private to com.authcore.config; redeclared here the
    // same way MachineAccessIntegrationTest does.
    private static final String DEMO_API_KEY = "ak_demo_reporting_job_local_only_0000000000";

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
        headers.set("X-API-Key", DEMO_API_KEY);
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
