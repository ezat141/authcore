package com.authcore.client;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

/**
 * Accepts a client's previous secret while its overlap window is open.
 *
 * <p>Spring's own provider compares against the one secret stored on the client and
 * knows nothing about rotation. This one runs as an additional provider: when a
 * presented secret is not the current one, {@code ProviderManager} carries on down the
 * list rather than stopping, so this gets a chance to match it against recently
 * superseded secrets.
 *
 * <p>It returns {@code null} rather than throwing whenever it cannot help — an unknown
 * client, a public client, a secret that matches nothing. Throwing here would replace
 * the real provider's failure with this one's and make a plain wrong password look like
 * a rotation problem.
 */
public class PreviousSecretAuthenticationProvider implements AuthenticationProvider {

    private static final Logger log = LoggerFactory.getLogger(PreviousSecretAuthenticationProvider.class);

    private final RegisteredClientRepository registeredClientRepository;
    private final ClientSecretRotationStore rotationStore;
    private final PasswordEncoder passwordEncoder;

    public PreviousSecretAuthenticationProvider(RegisteredClientRepository registeredClientRepository,
                                                ClientSecretRotationStore rotationStore,
                                                PasswordEncoder passwordEncoder) {
        this.registeredClientRepository = registeredClientRepository;
        this.rotationStore = rotationStore;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        OAuth2ClientAuthenticationToken clientAuthentication = (OAuth2ClientAuthenticationToken) authentication;

        ClientAuthenticationMethod method = clientAuthentication.getClientAuthenticationMethod();
        if (!ClientAuthenticationMethod.CLIENT_SECRET_BASIC.equals(method)
                && !ClientAuthenticationMethod.CLIENT_SECRET_POST.equals(method)) {
            return null;
        }

        String clientId = clientAuthentication.getPrincipal().toString();
        Object credentials = clientAuthentication.getCredentials();
        if (credentials == null) {
            return null;
        }
        String presentedSecret = credentials.toString();

        RegisteredClient registeredClient = registeredClientRepository.findByClientId(clientId);
        if (registeredClient == null
                || !registeredClient.getClientAuthenticationMethods().contains(method)) {
            return null;
        }

        for (String previousSecret : rotationStore.findAcceptedPreviousSecrets(clientId)) {
            if (passwordEncoder.matches(presentedSecret, previousSecret)) {
                // Worth a log line: it means a deployment somewhere is still on the old
                // secret, which is exactly what an operator needs to know before the
                // window closes.
                log.info("Client {} authenticated with a superseded secret still inside its overlap window",
                        clientId);
                return new OAuth2ClientAuthenticationToken(registeredClient, method, presentedSecret);
            }
        }

        return null;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return OAuth2ClientAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
