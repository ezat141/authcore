package com.authcore.api;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * Exercises method-level authorization.
 *
 * <p>The M4 endpoints are guarded by URL rules in the filter chain, which is the right
 * tool when the rule is "this path needs this scope". These are guarded at the method,
 * which is what you need once the answer depends on the arguments — the URL pattern
 * cannot see which account is being requested.
 */
@RestController
@RequestMapping("/api/accounts")
public class AccountApiController {

    /** Any authenticated caller may read their own profile. */
    @GetMapping("/me")
    public Map<String, Object> me(Authentication authentication) {
        return Map.of(
                "username", authentication.getName(),
                "authorities", authorities(authentication));
    }

    /**
     * Owner-or-admin: {@code hasPermission} resolves to
     * {@link com.authcore.security.AuthCorePermissionEvaluator}, which lets a caller
     * through for their own account, or for any account with {@code accounts:read:all}.
     */
    @GetMapping("/{ownerId}")
    @PreAuthorize("hasPermission(#ownerId, 'Account', 'read')")
    public Map<String, Object> account(@PathVariable String ownerId, Authentication authentication) {
        return Map.of(
                "ownerId", ownerId,
                "requestedBy", authentication.getName(),
                "ownAccount", ownerId.equals(authentication.getName()),
                "balance", 1234.56);
    }

    /** Flat capability check — no per-record logic needed. */
    @PostMapping("/{ownerId}/payments")
    @PreAuthorize("hasAuthority('payments:write')")
    public Map<String, Object> createPayment(@PathVariable String ownerId, Authentication authentication) {
        return Map.of(
                "ownerId", ownerId,
                "createdBy", authentication.getName(),
                "status", "PENDING");
    }

    /** Role check rather than permission — coarse administrative gate. */
    @GetMapping("/admin/all")
    @PreAuthorize("hasRole('ADMIN')")
    public Map<String, Object> allAccounts(Authentication authentication) {
        return Map.of(
                "requestedBy", authentication.getName(),
                "accounts", List.of("ezzat", "admin"));
    }

    private static List<String> authorities(Authentication authentication) {
        return authentication.getAuthorities().stream()
                .map(Object::toString)
                .sorted()
                .toList();
    }
}
