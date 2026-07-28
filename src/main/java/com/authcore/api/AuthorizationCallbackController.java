package com.authcore.api;

import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Landing page for the registered {@code redirect_uri}.
 *
 * <p>A real client would exchange the code here. This server has no client application,
 * so the page simply shows what arrived — which matters more than it sounds: the redirect
 * target is {@code 127.0.0.1} while the login happened on {@code localhost}, and browsers
 * treat those as different hosts. No session cookie travels across, so without a public
 * handler here the authorization server would answer its own redirect with a login page
 * and the code would vanish from view.
 */
@RestController
public class AuthorizationCallbackController {

    @GetMapping(value = "/authorized", produces = MediaType.TEXT_HTML_VALUE)
    public String authorized(@RequestParam(required = false) String code,
                             @RequestParam(required = false) String error,
                             @RequestParam(name = "error_description", required = false) String errorDescription) {
        if (error != null) {
            return page("Authorization failed", escape(error),
                    errorDescription == null ? "" : escape(errorDescription));
        }
        if (code == null) {
            return page("Nothing to show",
                    "No authorization code in this request.",
                    "Start the flow at /oauth2/authorize.");
        }
        return page("Authorization code received", escape(code),
                "Exchange it at /oauth2/token with the matching code_verifier. Single use, expires shortly.");
    }

    private static String page(String heading, String value, String note) {
        return """
                <!doctype html>
                <html><head><meta charset="utf-8"><title>AuthCore</title>
                <style>
                  body{font-family:system-ui,sans-serif;max-width:52rem;margin:4rem auto;padding:0 1rem;line-height:1.5}
                  h1{font-size:1.25rem}
                  code{display:block;word-break:break-all;background:#f4f4f5;padding:1rem;border-radius:6px;
                       font-family:ui-monospace,monospace;font-size:.9rem}
                  p{color:#52525b;font-size:.9rem}
                </style></head>
                <body><h1>%s</h1><code>%s</code><p>%s</p></body></html>
                """.formatted(heading, value, note);
    }

    private static String escape(String value) {
        return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }
}
