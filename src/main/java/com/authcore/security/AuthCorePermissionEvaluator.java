package com.authcore.security;

import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.io.Serializable;

/**
 * Answers {@code hasPermission(...)} in {@code @PreAuthorize} expressions, covering the
 * case a static authority check cannot: "may this caller touch <em>this particular</em>
 * record?"
 *
 * <p>A plain {@code hasAuthority('accounts:read')} is all-or-nothing — grant it and the
 * holder reads every account. Ownership is the missing half: a user may always reach
 * their own resource, while reaching someone else's needs an explicit {@code :all}
 * permission. That keeps the common case ungranted and the privileged case deliberate.
 */
public class AuthCorePermissionEvaluator implements PermissionEvaluator {

    private static final String ALL_SUFFIX = ":all";

    @Override
    public boolean hasPermission(Authentication authentication, Object targetDomainObject, Object permission) {
        if (authentication == null || !authentication.isAuthenticated() || targetDomainObject == null) {
            return false;
        }
        return hasPermission(authentication, String.valueOf(targetDomainObject),
                targetDomainObject.getClass().getSimpleName(), permission);
    }

    @Override
    public boolean hasPermission(Authentication authentication, Serializable targetId,
                                 String targetType, Object permission) {
        if (authentication == null || !authentication.isAuthenticated() || permission == null) {
            return false;
        }

        // e.g. targetType "Account" + permission "read" -> "accounts:read"
        String base = targetType.toLowerCase() + "s:" + permission;

        // A blanket grant wins outright, whoever owns the record.
        if (hasAuthority(authentication, base + ALL_SUFFIX)) {
            return true;
        }

        // Otherwise the caller must both hold the permission and own the record.
        return hasAuthority(authentication, base) && isOwner(authentication, targetId);
    }

    private static boolean isOwner(Authentication authentication, Serializable targetId) {
        return targetId != null && targetId.toString().equals(authentication.getName());
    }

    private static boolean hasAuthority(Authentication authentication, String authority) {
        for (GrantedAuthority granted : authentication.getAuthorities()) {
            if (authority.equals(granted.getAuthority())) {
                return true;
            }
        }
        return false;
    }
}
