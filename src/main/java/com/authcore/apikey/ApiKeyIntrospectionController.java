package com.authcore.apikey;

import org.springframework.http.HttpStatus;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Lets a trusted caller ask whether an API key is valid and what it grants.
 *
 * <p>Exists because the platform's other services cannot answer that question. The
 * {@code api_keys} table is AuthCore's, and a second service reaching into it directly
 * would put two services on one schema — the property this platform exists not to have.
 * AuthCore owns identity, and "is this credential valid" is an identity question.
 *
 * <p>Sitting on the {@code /api/**} chain already keeps out anonymous callers, but nothing
 * here or in {@code AuthorizationServerConfig} yet requires the specific {@code
 * SCOPE_apikeys:introspect} scope. Until that rule is added, any authenticated caller —
 * including a low-privilege key such as the seeded demo one — can use this endpoint as an
 * oracle for testing whether some other key is still valid. Tracked as follow-up work, not
 * a gap discovered later.
 */
@RestController
@RequestMapping("/api/internal/api-keys")
public class ApiKeyIntrospectionController {

    private final ApiKeyStore apiKeyStore;

    public ApiKeyIntrospectionController(ApiKeyStore apiKeyStore) {
        this.apiKeyStore = apiKeyStore;
    }

    @PostMapping("/introspect")
    public ApiKeyIntrospectionResponse introspect(@RequestBody ApiKeyIntrospectionRequest request) {
        // Unreachable over HTTP: Spring rejects a missing, empty, or literal-`null` body with
        // HttpMessageNotReadableException before this method runs (see handleMalformedBody
        // below), so request is never null here. This guards a direct programmatic call, e.g.
        // introspect(null) from another bean in-process.
        if (request == null || !StringUtils.hasText(request.key())) {
            return ApiKeyIntrospectionResponse.inactive();
        }

        return apiKeyStore.findByRawKey(request.key())
                .filter(ApiKey::isUsable)
                .map(apiKey -> {
                    // Keeps last_used_at tracking real validation. Note that GateKeeper
                    // caches this answer, so the column means "last validated at the
                    // source, accurate to within the gateway's cache TTL" rather than
                    // "last used" — see the M3 design, section 10.
                    apiKeyStore.touchLastUsed(apiKey.id());
                    return ApiKeyIntrospectionResponse.of(apiKey);
                })
                .orElseGet(ApiKeyIntrospectionResponse::inactive);
    }

    /**
     * Without this, an unparseable body's {@link HttpMessageNotReadableException} goes
     * unhandled here, and Boot's error handling forwards the request to {@code /error} to
     * render it. That forwarded request no longer matches this chain's {@code
     * securityMatcher("/api/**")} in {@code AuthorizationServerConfig}, so it falls through to
     * the second chain's {@code anyRequest().authenticated()} - which has no filter that
     * recognizes {@code X-API-Key}, only {@code formLogin()} - and comes back a 302 redirect
     * to the login page instead of a 400. A machine caller like GateKeeper gets an HTML login
     * page where it expected a JSON answer, with no clean way to tell that apart from its own
     * credential being refused. Handling it here resolves it within the original dispatch,
     * before any forward can happen.
     */
    @ExceptionHandler(HttpMessageNotReadableException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Map<String, String> handleMalformedBody(HttpMessageNotReadableException ex) {
        return Map.of("error", "invalid_request", "error_description", ex.getMessage());
    }
}
