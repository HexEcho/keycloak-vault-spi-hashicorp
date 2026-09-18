/*
 * Copyright 2026 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.github.sakc.keycloak.vault.hashicorp.clientauth;

import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.keycloak.OAuth2Constants;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.ClientAuthenticationFlowContext;
import org.keycloak.authentication.authenticators.client.ClientAuthUtil;
import org.keycloak.authentication.authenticators.client.ClientIdAndSecretAuthenticator;
import org.keycloak.models.ClientModel;
import org.keycloak.protocol.oidc.OIDCClientSecretConfigWrapper;
import org.keycloak.util.BasicAuthHelper;

/**
 * Same as Keycloak's {@code client-secret} authenticator, but validates against Vault-resolved secrets
 * (Keycloak 26.6 behaviour on 26.4.x). Selected via higher {@link #order()} with the same provider id.
 */
public class VaultAwareClientIdAndSecretAuthenticator extends ClientIdAndSecretAuthenticator {

    @Override
    public void authenticateClient(ClientAuthenticationFlowContext context) {
        String clientId = null;
        String clientSecret = null;

        String authorizationHeader = context.getHttpRequest().getHttpHeaders().getRequestHeaders()
                .getFirst(HttpHeaders.AUTHORIZATION);

        MediaType mediaType = context.getHttpRequest().getHttpHeaders().getMediaType();
        boolean hasFormData = mediaType != null && mediaType.isCompatible(MediaType.APPLICATION_FORM_URLENCODED_TYPE);
        MultivaluedMap<String, String> formData = hasFormData ? context.getHttpRequest().getDecodedFormParameters() : null;

        if (authorizationHeader != null) {
            String[] usernameSecret = BasicAuthHelper.RFC6749.parseHeader(authorizationHeader);
            if (usernameSecret != null) {
                clientId = usernameSecret[0];
                clientSecret = usernameSecret[1];
            } else if (formData != null && !formData.containsKey(OAuth2Constants.CLIENT_ID)) {
                Response challengeResponse = Response.status(Response.Status.UNAUTHORIZED)
                        .header(HttpHeaders.WWW_AUTHENTICATE, "Basic realm=\"" + context.getRealm().getName() + "\"")
                        .build();
                context.challenge(challengeResponse);
                return;
            }
        }

        if (formData != null) {
            if (formData.containsKey(OAuth2Constants.CLIENT_ID)) {
                clientId = formData.getFirst(OAuth2Constants.CLIENT_ID);
            }
            if (formData.containsKey(OAuth2Constants.CLIENT_SECRET)) {
                clientSecret = formData.getFirst(OAuth2Constants.CLIENT_SECRET);
            }
        }

        if (clientId == null) {
            clientId = context.getSession().getAttribute("client_id", String.class);
        }

        if (clientId == null) {
            Response challengeResponse = ClientAuthUtil.errorResponse(Response.Status.BAD_REQUEST.getStatusCode(),
                    "invalid_client", "Missing client_id parameter");
            context.challenge(challengeResponse);
            return;
        }

        context.getEvent().client(clientId);

        ClientModel client = context.getSession().clients().getClientByClientId(context.getRealm(), clientId);
        if (client == null) {
            context.failure(AuthenticationFlowError.CLIENT_NOT_FOUND, null);
            return;
        }

        context.setClient(client);

        if (!client.isEnabled()) {
            context.failure(AuthenticationFlowError.CLIENT_DISABLED, null);
            return;
        }

        if (client.isPublicClient()) {
            context.success();
            return;
        }

        if (clientSecret == null) {
            Response challengeResponse = ClientAuthUtil.errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(),
                    "unauthorized_client", "Invalid client or Invalid client credentials");
            context.challenge(challengeResponse);
            return;
        }

        if (client.getSecret() == null) {
            reportFailedAuth(context);
            return;
        }

        OIDCClientSecretConfigWrapper wrapper = OIDCClientSecretConfigWrapper.fromClientModel(client);
        if (!ClientSecretVaultMatcher.matchesCurrent(context.getSession(), client.getSecret(), clientSecret)
                && !ClientSecretVaultMatcher.matchesRotated(context.getSession(), wrapper, clientSecret)) {
            reportFailedAuth(context);
            return;
        }

        if (wrapper.isClientSecretExpired()) {
            reportFailedAuth(context);
            return;
        }

        context.success();
    }

    @Override
    public int order() {
        return super.order() + 10;
    }

    @Override
    public String getHelpText() {
        return "Validates client_id and client_secret, resolving ${vault.key} via the configured Vault SPI "
                + "(same behaviour as Keycloak 26.6).";
    }

    private void reportFailedAuth(ClientAuthenticationFlowContext context) {
        Response challengeResponse = ClientAuthUtil.errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(),
                "unauthorized_client", "Invalid client or Invalid client credentials");
        context.failure(AuthenticationFlowError.INVALID_CLIENT_CREDENTIALS, challengeResponse);
    }
}
