package com.authcore;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Import;
import org.springframework.web.client.RestTemplate;
import org.springframework.http.ResponseEntity;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Import(TestcontainersConfiguration.class)
class OidcEndpointsTest {

    @LocalServerPort
    private int port;

    private final RestTemplate http = new RestTemplate();

    @Test
    @SuppressWarnings("unchecked")
    void discoveryDocumentIsPublicAndContainsRequiredFields() {
        ResponseEntity<Map> response = http.getForEntity(
                "http://localhost:" + port + "/.well-known/openid-configuration", Map.class);

        assertThat(response.getStatusCode().value()).isEqualTo(200);
        assertThat(response.getBody())
                .containsKey("issuer")
                .containsKey("token_endpoint")
                .containsKey("jwks_uri")
                .containsKey("authorization_endpoint");
    }

    @Test
    @SuppressWarnings("unchecked")
    void jwksEndpointIsPublicAndReturnsRsaKey() {
        ResponseEntity<Map> response = http.getForEntity(
                "http://localhost:" + port + "/oauth2/jwks", Map.class);

        assertThat(response.getStatusCode().value()).isEqualTo(200);
        List<Map<String, Object>> keys = (List<Map<String, Object>>) response.getBody().get("keys");
        assertThat(keys).isNotEmpty();
        assertThat(keys.get(0))
                .containsKey("kid")
                .containsEntry("kty", "RSA");
    }
}
