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

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Supplier;

/**
 * Authenticates with Vault's Kubernetes auth method
 * ({@code POST /v1/auth/{mount}/login} with {@code role} and {@code jwt}).
 *
 * <p>The service-account JWT is read fresh from disk for every login attempt: it is never
 * cached in a field, never logged, and never included in an exception message. Only the
 * resulting Vault client token is cached, and only until ~90% of its lease duration.</p>
 *
 * <p>A double-checked lock ensures concurrent callers do not each trigger a separate login
 * (authentication stampede): the first caller authenticates, the rest wait for the same result.</p>
 */
public final class KubernetesTokenProvider implements VaultTokenProvider {

    private static final Logger log = Logger.getLogger(KubernetesTokenProvider.class);

    private final HashicorpVaultClient client;
    private final String mountPath;
    private final String role;
    private final Supplier<String> jwtSupplier;
    private final ReentrantLock authLock = new ReentrantLock();
    private volatile String cachedToken;
    private volatile long tokenExpiresAtMs;

    /** Package-visible for tests: allows injecting a JWT source instead of a real file. */
    KubernetesTokenProvider(HashicorpVaultClient client, String mountPath, String role, Supplier<String> jwtSupplier) {
        this.client = client;
        this.mountPath = mountPath;
        this.role = role;
        this.jwtSupplier = jwtSupplier;
    }

    public static KubernetesTokenProvider forJwtFile(HashicorpVaultClient client, String mountPath, String role,
                                                      String jwtFilePath) {
        Path path = jwtFilePath == null || jwtFilePath.isBlank() ? null : Path.of(jwtFilePath);
        return new KubernetesTokenProvider(client, mountPath, role, () -> readJwtFile(path));
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
            if (role == null || role.isBlank()) {
                log.error("Kubernetes auth-method selected but kubernetes-role is not configured.");
                return null;
            }
            String jwt = jwtSupplier.get();
            if (jwt == null || jwt.isBlank()) {
                log.error("Kubernetes authentication failed: no service account JWT is available.");
                return null;
            }
            JsonNode response;
            try {
                response = client.login(session, "auth/" + mountPath + "/login", Map.of("role", role, "jwt", jwt));
            } finally {
                jwt = null; // never retained beyond the single login call
            }
            VaultAuthTokens.ParsedToken parsed = VaultAuthTokens.parseLogin(response);
            if (parsed == null) {
                log.error("Kubernetes authentication with Vault failed.");
                return null;
            }
            cachedToken = parsed.token();
            tokenExpiresAtMs = parsed.expiresAtMs(System.currentTimeMillis());
            log.debug("Kubernetes authentication succeeded; token cached.");
            return cachedToken;
        } catch (Exception e) {
            // Message is a fixed string; never interpolate the JWT or exception detail that could carry it.
            log.error("Error during Kubernetes authentication.", e);
            return null;
        } finally {
            authLock.unlock();
        }
    }

    private static String readJwtFile(Path path) {
        if (path == null) {
            log.error("Kubernetes auth-method selected but kubernetes-jwt-path is not configured.");
            return null;
        }
        if (!Files.isReadable(path)) {
            log.errorf("Kubernetes service account token file is not readable: %s", path);
            return null;
        }
        try {
            String jwt = Files.readString(path, StandardCharsets.UTF_8).trim();
            if (jwt.isEmpty()) {
                log.errorf("Kubernetes service account token file is empty: %s", path);
                return null;
            }
            return jwt;
        } catch (IOException e) {
            log.errorf("Failed to read Kubernetes service account token file: %s", path);
            return null;
        }
    }
}
