package com.authcore.api;

import com.authcore.client.ClientSecretRotationService;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * Operator surface for client credentials.
 */
@RestController
@RequestMapping("/api/admin/clients")
public class ClientAdminController {

    private final ClientSecretRotationService rotationService;

    public ClientAdminController(ClientSecretRotationService rotationService) {
        this.rotationService = rotationService;
    }

    /**
     * Issues a new secret and returns it once, in clear text.
     *
     * <p>Only time it is ever readable — it is stored hashed, so a caller who loses it
     * has to rotate again rather than look it up.
     */
    @PostMapping("/{clientId}/rotate-secret")
    @PreAuthorize("hasAuthority('clients:rotate-secret')")
    public Map<String, Object> rotateSecret(@PathVariable String clientId) {
        ClientSecretRotationService.RotationResult result = rotationService.rotate(clientId);

        return Map.of(
                "clientId", clientId,
                "newSecret", result.newSecret(),
                "previousSecretAcceptedUntil", result.previousSecretAcceptedUntil().toString(),
                "note", "Store this now; it cannot be retrieved again. "
                        + "The previous secret keeps working until the time above, "
                        + "so deployments can be updated without downtime.");
    }

    /** Closes the overlap immediately, for when the old secret is known to have leaked. */
    @PostMapping("/{clientId}/revoke-previous-secrets")
    @PreAuthorize("hasAuthority('clients:rotate-secret')")
    public Map<String, Object> revokePrevious(@PathVariable String clientId) {
        return Map.of(
                "clientId", clientId,
                "revoked", rotationService.revokePreviousSecrets(clientId));
    }

    @ExceptionHandler(IllegalArgumentException.class)
    @ResponseStatus(org.springframework.http.HttpStatus.BAD_REQUEST)
    public Map<String, String> handleUnknownClient(IllegalArgumentException ex) {
        return Map.of("error", "invalid_request", "error_description", ex.getMessage());
    }
}
