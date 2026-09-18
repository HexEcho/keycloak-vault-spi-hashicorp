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
package io.github.sakc.keycloak.vault.hashicorp.auth;

import com.fasterxml.jackson.databind.JsonNode;
import io.github.sakc.keycloak.vault.hashicorp.HashicorpVaultClient;
import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;

import java.util.Map;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Authenticates with Vault AppRole and caches the client token until 90% of lease_duration.
 */
public final class AppRoleTokenProvider implements VaultTokenProvider {

    private static final Logger log = Logger.getLogger(AppRoleTokenProvider.class);

    private final HashicorpVaultClient client;
    private final String mountPath;
    private final String roleId;
    private volatile String secretId;
    private final ReentrantLock authLock = new ReentrantLock();
    private volatile String cachedToken;
    private volatile long tokenExpiresAtMs;

    public AppRoleTokenProvider(HashicorpVaultClient client, String mountPath, String roleId, String secretId) {
        this.client = client;
        this.mountPath = mountPath;
        this.roleId = roleId;
        this.secretId = secretId;
    }

    @Override
    public String getToken(KeycloakSession session) {
        if (cachedToken != null && System.currentTimeMillis() < tokenExpiresAtMs) {
            return cachedToken;
        }
        return authenticate(session);
    }

    @Override
    public void invalidate() {
        authLock.lock();
        try {
            cachedToken = null;
            tokenExpiresAtMs = 0;
        } finally {
            authLock.unlock();
        }
    }

    @Override
    public void close() {
        secretId = null;
        cachedToken = null;
    }

    private String authenticate(KeycloakSession session) {
        authLock.lock();
        try {
            if (cachedToken != null && System.currentTimeMillis() < tokenExpiresAtMs) {
                return cachedToken;
            }
            String currentSecretId = this.secretId;
            if (roleId == null || roleId.isBlank() || currentSecretId == null || currentSecretId.isBlank()) {
                log.error("AppRole role-id or secret-id is missing; cannot authenticate.");
                return null;
            }
            JsonNode body = client.login(session, "auth/" + mountPath + "/login",
                    Map.of("role_id", roleId, "secret_id", currentSecretId));
            VaultAuthTokens.ParsedToken parsed = VaultAuthTokens.parseLogin(body);
            if (parsed == null) {
                return null;
            }
            cachedToken = parsed.token();
            tokenExpiresAtMs = parsed.expiresAtMs(System.currentTimeMillis());
            log.debug("AppRole authentication succeeded; token cached.");
            return cachedToken;
        } catch (Exception e) {
            log.error("Error during AppRole authentication.", e);
            return null;
        } finally {
            authLock.unlock();
        }
    }
}
