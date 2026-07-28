package com.authcore.api;

import com.authcore.keys.JpaJwkSource;
import com.authcore.keys.SigningKey;
import com.authcore.keys.SigningKeyService;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * Operator surface for signing keys.
 *
 * <p>Rotation is the response to a suspected key compromise, so it is guarded by its own
 * permission rather than a general admin role — the set of people who should be able to
 * re-key the server is smaller than the set who administer it.
 */
@RestController
@RequestMapping("/api/admin/keys")
public class KeyAdminController {

    private final SigningKeyService signingKeyService;
    private final JpaJwkSource jwkSource;

    public KeyAdminController(SigningKeyService signingKeyService, JpaJwkSource jwkSource) {
        this.signingKeyService = signingKeyService;
        this.jwkSource = jwkSource;
    }

    @GetMapping
    @PreAuthorize("hasAuthority('keys:read')")
    public Map<String, Object> list() {
        return Map.of("keys", signingKeyService.findAll().stream().map(KeyAdminController::describe).toList());
    }

    @PostMapping("/rotate")
    @PreAuthorize("hasAuthority('keys:rotate')")
    public Map<String, Object> rotate() {
        SigningKey active = signingKeyService.rotate();
        // The cache would otherwise keep signing with the retired key for its TTL.
        jwkSource.invalidate();

        return Map.of(
                "rotated", true,
                "activeKid", active.getKid(),
                "keys", signingKeyService.findAll().stream().map(KeyAdminController::describe).toList(),
                "note", "Tokens signed by retired keys stay valid until they expire.");
    }

    private static Map<String, Object> describe(SigningKey key) {
        return Map.of(
                "kid", key.getKid(),
                "status", key.getStatus().name(),
                "createdAt", key.getCreatedAt().toString());
    }
}
