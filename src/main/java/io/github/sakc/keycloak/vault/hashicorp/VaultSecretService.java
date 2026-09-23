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
package io.github.sakc.keycloak.vault.hashicorp;

import io.github.sakc.keycloak.vault.hashicorp.auth.VaultTokenProvider;
import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;

/**
 * Sits between the Keycloak SPI layer ({@code HashicorpVaultProvider}, {@code ClientSecretVaultSync})
 * and the {@link HashicorpVaultClient} HTTP layer. Owns the single, deterministic authentication
 * lifecycle so it is implemented once instead of duplicated at every call site:
 *
 * <pre>
 * get token -&gt; Vault request -&gt; success
 *                            -&gt; authorization failure -&gt; invalidate token -&gt; authenticate -&gt; retry ONCE
 * </pre>
 *
 * A second authorization failure after the single retry is returned to the caller as-is; it never
 * loops back into another authenticate attempt.
 */
public final class VaultSecretService {

    private static final Logger log = Logger.getLogger(VaultSecretService.class);

    private final HashicorpVaultClient client;
    private final VaultTokenProvider tokenProvider;

    public VaultSecretService(HashicorpVaultClient client, VaultTokenProvider tokenProvider) {
        this.client = client;
        this.tokenProvider = tokenProvider;
    }

    public HashicorpVaultClient.SecretLookup readSecret(KeycloakSession session, String vaultKey) {
        String token = tokenProvider.getToken(session);
        if (token == null) {
            log.warn("Vault token provider returned null; cannot fetch secret.");
            return new HashicorpVaultClient.SecretLookup(0, null);
        }
        HashicorpVaultClient.SecretLookup lookup = client.readSecret(session, token, vaultKey);
        if (lookup.isForbidden()) {
            String refreshed = reauthenticate(session);
            if (refreshed != null) {
                lookup = client.readSecret(session, refreshed, vaultKey);
            }
        }
        return lookup;
    }

    public HashicorpVaultClient.WriteResult writeSecret(KeycloakSession session, String vaultKey, String secret) {
        String token = tokenProvider.getToken(session);
        if (token == null) {
            log.warn("Vault token provider returned null; cannot write secret.");
            return new HashicorpVaultClient.WriteResult(0);
        }
        HashicorpVaultClient.WriteResult result = client.writeSecret(session, token, vaultKey, secret);
        if (result.isForbidden()) {
            String refreshed = reauthenticate(session);
            if (refreshed != null) {
                result = client.writeSecret(session, refreshed, vaultKey, secret);
            }
        }
        return result;
    }

    public HashicorpVaultClient.DeleteResult deleteSecret(KeycloakSession session, String vaultKey) {
        String token = tokenProvider.getToken(session);
        if (token == null) {
            log.warn("Vault token provider returned null; cannot delete secret.");
            return new HashicorpVaultClient.DeleteResult(0);
        }
        HashicorpVaultClient.DeleteResult result = client.deleteSecret(session, token, vaultKey);
        if (result.isForbidden()) {
            String refreshed = reauthenticate(session);
            if (refreshed != null) {
                result = client.deleteSecret(session, refreshed, vaultKey);
            }
        }
        return result;
    }

    /**
     * Invalidates the cached token and authenticates exactly once. {@link VaultTokenProvider}
     * implementations serialize concurrent authentication attempts internally, so parallel
     * callers hitting a 403 at the same time still trigger a single Vault login.
     */
    private String reauthenticate(KeycloakSession session) {
        tokenProvider.invalidate();
        String refreshed = tokenProvider.getToken(session);
        if (refreshed == null) {
            log.warn("Vault re-authentication after an authorization failure did not produce a usable token.");
        } else {
            log.info("Vault authentication refreshed after an authorization failure; retrying the request once.");
        }
        return refreshed;
    }
}
