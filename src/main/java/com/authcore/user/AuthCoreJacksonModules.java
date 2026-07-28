package com.authcore.user;

import org.springframework.security.jackson.SecurityJacksonModules;
import org.springframework.security.oauth2.server.authorization.jackson.OAuth2AuthorizationServerJacksonModule;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.jsontype.BasicPolymorphicTypeValidator;

/**
 * Builds the {@link JsonMapper} the JDBC authorization service uses for the
 * {@code attributes} column.
 *
 * <p>Jackson 3 here, not Jackson 2. Spring Boot 4 ships {@code tools.jackson}, and
 * Spring Authorization Server carries adapters for both — its {@code OAuth2Authorization*}
 * mappers are the Jackson 2 pair, while the {@code JsonMapper*} ones are Jackson 3.
 *
 * <p>Two separate things are needed to round-trip a custom principal, and having only one
 * still fails:
 * <ul>
 *   <li>a <b>mixin</b>, so Jackson knows which constructor to call; and</li>
 *   <li>an entry in the <b>polymorphic type validator</b>, so the class is allowed to be
 *       named as a type at all.</li>
 * </ul>
 * The validator is a deserialization gadget defence — it refuses to instantiate arbitrary
 * classes named in stored JSON. Since the {@code attributes} column is data that comes
 * back into the application, that protection is worth keeping narrow rather than
 * disabling: only this one class is added to it.
 */
public final class AuthCoreJacksonModules {

    private AuthCoreJacksonModules() {
    }

    public static JsonMapper authorizationJsonMapper() {
        ClassLoader classLoader = AuthCoreJacksonModules.class.getClassLoader();

        BasicPolymorphicTypeValidator.Builder typeValidator = BasicPolymorphicTypeValidator.builder()
                .allowIfSubType(AuthCoreUserPrincipal.class);

        return JsonMapper.builder()
                // The security modules install the allowlist and default typing; the SAS
                // module handles its own authorization types.
                .addModules(SecurityJacksonModules.getModules(classLoader, typeValidator))
                .addModule(new OAuth2AuthorizationServerJacksonModule())
                .addMixIn(AuthCoreUserPrincipal.class, AuthCoreUserPrincipalMixin.class)
                .build();
    }
}
