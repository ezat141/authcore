package com.authcore.api;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/**
 * Stand-in resource API for exercising machine-to-machine access.
 *
 * <p>Both endpoints are reachable with either a client-credentials bearer token or an
 * {@code X-API-Key}; the scope rules in the security config don't care which. The
 * response echoes back how the caller authenticated so a demo makes that visible.
 */
@RestController
@RequestMapping("/api/machine")
public class MachineApiController {

    @GetMapping("/payments")
    public Map<String, Object> readPayments(Authentication authentication) {
        return Map.of(
                "action", "read",
                "caller", describeCaller(authentication),
                "authenticatedVia", describeMechanism(authentication),
                "authorities", authorities(authentication),
                "payments", List.of(
                        Map.of("id", "pmt_001", "amount", 4200, "currency", "EUR"),
                        Map.of("id", "pmt_002", "amount", 1350, "currency", "EUR")));
    }

    @PostMapping("/payments")
    public Map<String, Object> writePayment(Authentication authentication) {
        return Map.of(
                "action", "write",
                "caller", describeCaller(authentication),
                "authenticatedVia", describeMechanism(authentication),
                "authorities", authorities(authentication),
                "created", Map.of("id", "pmt_003", "status", "PENDING"));
    }

    private static String describeCaller(Authentication authentication) {
        return authentication == null ? "anonymous" : String.valueOf(authentication.getName());
    }

    private static String describeMechanism(Authentication authentication) {
        if (authentication == null) {
            return "none";
        }
        return authentication instanceof com.authcore.apikey.ApiKeyAuthenticationToken
                ? "api-key"
                : "bearer-jwt";
    }

    private static List<String> authorities(Authentication authentication) {
        if (authentication == null) {
            return List.of();
        }
        return authentication.getAuthorities().stream()
                .map(Object::toString)
                .sorted()
                .toList();
    }
}
