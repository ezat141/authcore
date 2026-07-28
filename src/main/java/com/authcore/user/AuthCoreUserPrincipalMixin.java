package com.authcore.user;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

/**
 * Teaches Jackson how to rebuild {@link AuthCoreUserPrincipal} from a stored authorization.
 *
 * <p>{@code JdbcOAuth2AuthorizationService} serialises the authenticated principal into the
 * {@code attributes} column and reads it back at token time, using an {@code ObjectMapper}
 * whose type resolver only accepts an allowlist of classes. Writing works without any of
 * this — which is the trap. The row saves cleanly, and the failure only appears later when
 * the code is exchanged and the row cannot be read back, surfacing as a bare 401 from the
 * token endpoint with nothing pointing at serialisation.
 *
 * <p>Registering this mixin puts the class on the allowlist and gives it a constructor
 * Jackson can call.
 */
@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS, include = JsonTypeInfo.As.PROPERTY)
@JsonAutoDetect(
        fieldVisibility = JsonAutoDetect.Visibility.ANY,
        getterVisibility = JsonAutoDetect.Visibility.NONE,
        isGetterVisibility = JsonAutoDetect.Visibility.NONE)
@JsonIgnoreProperties(ignoreUnknown = true)
abstract class AuthCoreUserPrincipalMixin {

    @JsonCreator
    AuthCoreUserPrincipalMixin(
            @JsonProperty("username") String username,
            @JsonProperty("password") String password,
            @JsonProperty("tenantSlug") String tenantSlug,
            @JsonProperty("enabled") boolean enabled,
            @JsonProperty("authorities") Collection<? extends GrantedAuthority> authorities) {
    }
}
