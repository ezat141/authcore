package com.authcore.token;

public record RefreshTokenRecord(
        String tokenHash,
        String familyId,
        String authorizationId,
        String principalName,
        boolean consumed) {
}
