package com.authcore.apikey;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.time.Instant;
import java.util.Set;

/**
 * Answers "is this key valid, and what does it grant". Never carries the key or its hash —
 * it answers a question, it does not echo the credential.
 *
 * <p>Unknown, disabled and expired keys all produce the same {@code active: false} with no
 * further detail. Distinguishing them would make this endpoint an enumeration oracle: a
 * caller able to tell "no such key" from "that key exists but is disabled" could confirm
 * which keys are real. AuthCore still surfaces the distinction internally, as two different
 * exception types — see {@link ApiKeyAuthenticationProvider}, which keeps its
 * DisabledException / CredentialsExpiredException split — so the diagnosis the caller is
 * denied is not lost.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record ApiKeyIntrospectionResponse(
        boolean active,
        String name,
        Set<String> scopes,
        Instant expiresAt) {

    public static ApiKeyIntrospectionResponse inactive() {
        return new ApiKeyIntrospectionResponse(false, null, null, null);
    }

    /** Caller must have already confirmed {@link ApiKey#isUsable()}. */
    public static ApiKeyIntrospectionResponse of(ApiKey apiKey) {
        return new ApiKeyIntrospectionResponse(
                true, apiKey.name(), apiKey.scopes(), apiKey.expiresAt());
    }
}
