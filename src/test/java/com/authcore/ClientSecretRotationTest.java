package com.authcore;

import com.authcore.client.ClientSecretRotationService;
import com.authcore.client.ClientSecretRotationStore;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Import;
import org.springframework.http.*;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The overlap window is the entire feature, so it is tested through real token requests:
 * both secrets must work at once, or rotation is still an outage.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Import(TestcontainersConfiguration.class)
class ClientSecretRotationTest {

    private static final String CLIENT_ID = "authcore-machine";
    private static final String ORIGINAL_SECRET = "machine-secret";

    @LocalServerPort
    private int port;

    @Autowired
    private ClientSecretRotationService rotationService;

    @Autowired
    private ClientSecretRotationStore rotationStore;

    @Autowired
    private RegisteredClientRepository registeredClientRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    private final RestTemplate http = new RestTemplate();

    /** Other tests authenticate with the seeded secret, so put it back afterwards. */
    @AfterEach
    void restoreSeededSecret() {
        rotationStore.revokePreviousSecrets(CLIENT_ID);

        RegisteredClient existing = registeredClientRepository.findByClientId(CLIENT_ID);
        registeredClientRepository.save(RegisteredClient.from(existing)
                .clientSecret(passwordEncoder.encode(ORIGINAL_SECRET))
                .build());
    }

    @Test
    void bothTheOldAndNewSecretWorkDuringTheOverlap() {
        assertThat(canGetToken(ORIGINAL_SECRET)).isTrue();

        String newSecret = rotationService.rotate(CLIENT_ID).newSecret();

        // The point of the whole exercise: a deployment that has not been updated yet
        // keeps working, while one that has also works.
        assertThat(canGetToken(newSecret)).isTrue();
        assertThat(canGetToken(ORIGINAL_SECRET)).isTrue();
    }

    @Test
    void theOldSecretStopsWorkingOnceTheOverlapIsRevoked() {
        String newSecret = rotationService.rotate(CLIENT_ID).newSecret();
        assertThat(canGetToken(ORIGINAL_SECRET)).isTrue();

        rotationService.revokePreviousSecrets(CLIENT_ID);

        assertThat(canGetToken(ORIGINAL_SECRET)).isFalse();
        assertThat(canGetToken(newSecret)).isTrue();
    }

    @Test
    void aWrongSecretIsStillRejectedDuringAnOverlap() {
        rotationService.rotate(CLIENT_ID);

        // The extra provider must widen what is accepted to exactly the previous
        // secret, not to anything at all.
        assertThat(canGetToken("not-the-secret")).isFalse();
    }

    @Test
    void rotationReportsWhenTheOldSecretStopsBeingAccepted() {
        var result = rotationService.rotate(CLIENT_ID);

        // An operator cannot plan the redeploy without knowing the deadline.
        assertThat(result.previousSecretAcceptedUntil()).isAfter(java.time.Instant.now());
        assertThat(result.newSecret()).isNotBlank().isNotEqualTo(ORIGINAL_SECRET);
    }

    @Test
    void rotatingAnUnknownClientIsRejected() {
        assertThatThrownBy(() -> rotationService.rotate("no-such-client"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Unknown client");
    }

    @Test
    void rotatingAPublicClientIsRejected() {
        // authcore-spa authenticates with NONE; giving it a secret would change how it
        // authenticates rather than rotating anything.
        assertThatThrownBy(() -> rotationService.rotate("authcore-spa"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("public");
    }

    @SuppressWarnings("rawtypes")
    private boolean canGetToken(String secret) {
        HttpHeaders headers = new HttpHeaders();
        headers.setBasicAuth(CLIENT_ID, secret);
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "client_credentials");
        form.add("scope", "payments:read");

        try {
            ResponseEntity<Map> response = http.postForEntity(
                    "http://localhost:" + port + "/oauth2/token",
                    new HttpEntity<>(form, headers), Map.class);
            return response.getStatusCode().is2xxSuccessful()
                    && response.getBody() != null
                    && response.getBody().get("access_token") != null;
        } catch (HttpClientErrorException ex) {
            return false;
        }
    }
}
