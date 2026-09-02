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
 * <p>Guarded by {@code SCOPE_apikeys:introspect} in {@code AuthorizationServerConfig}. Left
 * open it would be an oracle for testing stolen keys at line rate — and merely requiring
 * authentication is not enough, since any low-privilege key would then qualify.
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
     * the second chain's {@code anyRequest().authenticated()}, which has no filter that
     * recognizes {@code X-API-Key}. What comes back there is content-negotiated on the
     * forwarded request's {@code Accept} header, not a single fixed answer: a client
     * accepting {@code application/json}, a bare wildcard, or nothing in particular gets a
     * 401 with a {@code WWW-Authenticate: Bearer resource_metadata="..."} challenge -
     * plausibly contributed by {@code OAuth2AuthorizationServerConfigurer}'s own
     * resource-metadata support - while a client whose {@code Accept} includes any {@code
     * text/*} type, which includes RestTemplate's computed default, gets a 302 redirect to
     * the login page instead. Either way, a machine caller like GateKeeper gets something
     * other than the clean 400 it should, with no reliable way to tell either wrong answer
     * apart from its own credential being refused.
     *
     * <p>This only closes the gap for a body Spring itself cannot parse. Handling it here
     * keeps that specific failure inside the original dispatch, so it never reaches the
     * forward described above. A well-formed request can still trigger a different forward:
     * {@code text/html} in {@code Accept} makes response-writing fail with {@code
     * HttpMediaTypeNotAcceptableException}, since this endpoint has no converter for that
     * type, and that is a separate, pre-existing gap this handler does not address.
     */
    @ExceptionHandler(HttpMessageNotReadableException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Map<String, String> handleMalformedBody(HttpMessageNotReadableException ex) {
        return Map.of("error", "invalid_request", "error_description", ex.getMessage());
    }
}
