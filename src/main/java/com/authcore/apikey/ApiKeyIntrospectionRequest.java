package com.authcore.apikey;

/**
 * The key travels in a POST body, never in a path or query string. A credential in a URL
 * lands in access logs, proxy logs and Referer headers.
 */
public record ApiKeyIntrospectionRequest(String key) {
}
