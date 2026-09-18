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
 * Authenticates with Vault's TLS certificate auth method ({@code POST /v1/auth/{mount}/login}).
 * The client certificate is presented by Keycloak's outbound HTTP client (mTLS).
 */
public final class CertTokenProvider implements VaultTokenProvider {

    private static final Logger log = Logger.getLogger(CertTokenProvider.class);

    private final HashicorpVaultClient client;
    private final String mountPath;
    private final String certName;
    private final ReentrantLock authLock = new ReentrantLock();
    private volatile String cachedToken;
    private volatile long tokenExpiresAtMs;

    public CertTokenProvider(HashicorpVaultClient client, String mountPath, String certName) {
        this.client = client;
        this.mountPath = mountPath;
        this.certName = certName;
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
        cachedToken = null;
    }

    private String authenticate(KeycloakSession session) {
        authLock.lock();
        try {
            if (cachedToken != null && System.currentTimeMillis() < tokenExpiresAtMs) {
                return cachedToken;
            }
            Map<String, String> body = certName == null || certName.isBlank()
                    ? Map.of()
                    : Map.of("name", certName);
            JsonNode response = client.login(session, "auth/" + mountPath + "/login", body);
            VaultAuthTokens.ParsedToken parsed = VaultAuthTokens.parseLogin(response);
            if (parsed == null) {
                return null;
            }
            cachedToken = parsed.token();
            tokenExpiresAtMs = parsed.expiresAtMs(System.currentTimeMillis());
            log.debug("Vault certificate authentication succeeded; token cached.");
            return cachedToken;
        } catch (Exception e) {
            log.error("Error during Vault certificate authentication.", e);
            return null;
        } finally {
            authLock.unlock();
        }
    }
}
