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

import com.fasterxml.jackson.databind.JsonNode;
import io.github.sakc.keycloak.vault.hashicorp.exception.VaultException;
import org.apache.http.client.config.RequestConfig;
import org.jboss.logging.Logger;
import org.keycloak.http.simple.SimpleHttp;
import org.keycloak.http.simple.SimpleHttpRequest;
import org.keycloak.http.simple.SimpleHttpResponse;
import org.keycloak.models.KeycloakSession;
import org.keycloak.util.JsonSerialization;

import java.io.IOException;
import java.util.Map;
import java.util.function.Supplier;

/**
 * HashiCorp KV HTTP calls using Keycloak {@link SimpleHttp} (HttpClientProvider). Does not
 * construct its own HTTP client, but owns everything specific to talking to Vault: headers,
 * bounded timeouts, retry-with-backoff for transient failures, and mapping of Vault HTTP
 * responses to the {@link VaultException} hierarchy.
 */
public final class HashicorpVaultClient {

    private static final Logger log = Logger.getLogger(HashicorpVaultClient.class);

    private final HashicorpVaultConfig config;
    private final VaultRetryPolicy retryPolicy;
    private final RequestConfig requestConfig;

    public HashicorpVaultClient(HashicorpVaultConfig config) {
        this.config = config;
        this.retryPolicy = new VaultRetryPolicy(config.getRetryMaxAttempts(), config.getRetryInitialDelayMs(),
                config.getRetryMaxDelayMs());
        this.requestConfig = RequestConfig.custom()
                .setConnectTimeout((int) Math.min(Integer.MAX_VALUE, config.getConnectTimeoutMs()))
                .setSocketTimeout((int) Math.min(Integer.MAX_VALUE, config.getReadTimeoutMs()))
                .setConnectionRequestTimeout((int) Math.min(Integer.MAX_VALUE, config.getRequestTimeoutMs()))
                .build();
    }

    public SecretLookup readSecret(KeycloakSession session, String token, String vaultKey) {
        String url;
        try {
            url = secretUrl(config, vaultKey);
        } catch (IllegalArgumentException e) {
            log.warn("Refusing to read a secret for an unsafe Vault key.");
            return new SecretLookup(0, null);
        }
        String path = safePath(vaultKey);
        try (SimpleHttpResponse response = executeWithRetry("read-secret", path,
                () -> applyVaultHeaders(SimpleHttp.create(session).withRequestConfig(requestConfig)
                        .doGet(url), token)
                        .acceptJson())) {
            int status = response.getStatus();
            if (status == 404) {
                log.debugf("Vault secret lookup found nothing. path=%s status=%d", path, status);
                return new SecretLookup(status, null);
            }
            if (status == 403) {
                log.warnf("Vault secret lookup failed: authorization denied. path=%s status=%d", path, status);
                return new SecretLookup(status, null);
            }
            if (status < 200 || status >= 300) {
                logMappingFailure(VaultErrorMapper.mapStatus("read-secret", path, status));
                return new SecretLookup(status, null);
            }
            String body = response.asString();
            JsonNode root = JsonSerialization.mapper.readTree(body);
            String value = extractField(root, config.getKvVersion(), config.getKvField());
            if (value == null) {
                log.warnf("Vault secret lookup succeeded but field '%s' was missing. path=%s", config.getKvField(), path);
            }
            return new SecretLookup(status, value);
        } catch (VaultException e) {
            logMappingFailure(e);
            return new SecretLookup(e.getHttpStatus(), null);
        } catch (IOException e) {
            log.errorf(e, "Vault secret lookup failed unexpectedly. path=%s", path);
            return new SecretLookup(0, null);
        }
    }

    public WriteResult writeSecret(KeycloakSession session, String token, String vaultKey, String secret) {
        String url;
        try {
            url = secretUrl(config, vaultKey);
        } catch (IllegalArgumentException e) {
            log.warn("Refusing to write a secret for an unsafe Vault key.");
            return new WriteResult(0);
        }
        String path = safePath(vaultKey);
        try (SimpleHttpResponse response = executeWithRetry("write-secret", path,
                () -> applyVaultHeaders(SimpleHttp.create(session).withRequestConfig(requestConfig)
                        .doPut(url), token)
                        .json(writeBody(config, secret)))) {
            int status = response.getStatus();
            if (status < 200 || status >= 300) {
                logMappingFailure(VaultErrorMapper.mapStatus("write-secret", path, status));
            }
            return new WriteResult(status);
        } catch (VaultException e) {
            logMappingFailure(e);
            return new WriteResult(e.getHttpStatus());
        } catch (IOException e) {
            log.errorf(e, "Vault secret write failed unexpectedly. path=%s", path);
            return new WriteResult(0);
        }
    }

    public DeleteResult deleteSecret(KeycloakSession session, String token, String vaultKey) {
        String url;
        try {
            url = deleteUrl(config, vaultKey);
        } catch (IllegalArgumentException e) {
            log.warn("Refusing to delete a secret for an unsafe Vault key.");
            return new DeleteResult(0);
        }
        String path = safePath(vaultKey);
        try (SimpleHttpResponse response = executeWithRetry("delete-secret", path,
                () -> applyVaultHeaders(SimpleHttp.create(session).withRequestConfig(requestConfig)
                        .doDelete(url), token))) {
            int status = response.getStatus();
            if (status != 404 && (status < 200 || status >= 300)) {
                logMappingFailure(VaultErrorMapper.mapStatus("delete-secret", path, status));
            }
            return new DeleteResult(status);
        } catch (VaultException e) {
            logMappingFailure(e);
            return new DeleteResult(e.getHttpStatus());
        } catch (IOException e) {
            log.errorf(e, "Vault secret delete failed unexpectedly. path=%s", path);
            return new DeleteResult(0);
        }
    }

    public JsonNode login(KeycloakSession session, String loginPath, Map<String, String> body) throws IOException {
        String url = config.getUrl() + "/v1/" + stripLeadingSlash(loginPath);
        String path = safePath(loginPath);
        try (SimpleHttpResponse response = executeWithRetry("authenticate", path,
                () -> applyVaultHeaders(SimpleHttp.create(session).withRequestConfig(requestConfig)
                        .doPost(url), null)
                        .json(body))) {
            int status = response.getStatus();
            String responseBody = response.asString();
            if (status != 200) {
                logMappingFailure(VaultErrorMapper.mapLoginStatus(path, status));
                return null;
            }
            return JsonSerialization.mapper.readTree(responseBody);
        } catch (VaultException e) {
            logMappingFailure(e);
            return null;
        }
    }

    /**
     * {@code GET /v1/sys/health}. Never called on the hot secret-lookup path: intended for a
     * low-frequency background poller (see {@code VaultHealthChecker}) or manual diagnostics.
     * Never retried: a single failed poll is enough signal, and the next poll will try again.
     */
    public HealthStatus healthCheck(KeycloakSession session) {
        String url = config.getUrl() + "/v1/sys/health";
        long start = System.currentTimeMillis();
        try (SimpleHttpResponse response = SimpleHttp.create(session).withRequestConfig(requestConfig)
                .doGet(url)
                .acceptJson()
                .asResponse()) {
            int status = response.getStatus();
            long durationMs = System.currentTimeMillis() - start;
            // 200 = initialized/unsealed/active, 429 = standby, 473 = perf standby: all "up".
            boolean healthy = status == 200 || status == 429 || status == 473;
            if (healthy) {
                log.debugf("Vault health check succeeded. status=%d durationMs=%d", status, durationMs);
            } else {
                log.warnf("Vault health check reported an unhealthy status. status=%d durationMs=%d", status, durationMs);
            }
            return new HealthStatus(healthy, status, null);
        } catch (IOException e) {
            long durationMs = System.currentTimeMillis() - start;
            log.warnf("Vault health check failed. error=%s durationMs=%d", e.getClass().getSimpleName(), durationMs);
            return new HealthStatus(false, 0, e.getClass().getSimpleName());
        }
    }

    /**
     * Runs {@code requestSupplier} with bounded retry-with-backoff for transient failures
     * (429/500/502/503/504, connection resets/timeouts). Non-transient statuses (4xx other than
     * 429) and configuration errors are returned or thrown on the first attempt.
     */
    private SimpleHttpResponse executeWithRetry(String operation, String path, Supplier<SimpleHttpRequest> requestSupplier)
            throws IOException {
        int maxAttempts = retryPolicy.maxAttempts();
        for (int attempt = 1; attempt <= maxAttempts; attempt++) {
            long attemptStart = System.currentTimeMillis();
            try {
                SimpleHttpResponse response = requestSupplier.get().asResponse();
                int status = response.getStatus();
                if (VaultErrorMapper.isRetryableStatus(status)) {
                    long durationMs = System.currentTimeMillis() - attemptStart;
                    response.close();
                    if (retryPolicy.shouldRetry(attempt)) {
                        log.warnf("Vault request retrying. operation=%s path=%s status=%d attempt=%d/%d durationMs=%d",
                                operation, path, status, attempt, maxAttempts, durationMs);
                        sleep(retryPolicy.backoffDelayMs(attempt + 1));
                        continue;
                    }
                    log.warnf("Vault request exhausted retries. operation=%s path=%s status=%d attempts=%d",
                            operation, path, status, maxAttempts);
                    throw VaultErrorMapper.mapStatus(operation, path, status);
                }
                return response;
            } catch (IOException e) {
                long durationMs = System.currentTimeMillis() - attemptStart;
                if (retryPolicy.shouldRetry(attempt)) {
                    log.warnf("Vault request retrying after transport error. operation=%s path=%s error=%s attempt=%d/%d durationMs=%d",
                            operation, path, e.getClass().getSimpleName(), attempt, maxAttempts, durationMs);
                    sleep(retryPolicy.backoffDelayMs(attempt + 1));
                    continue;
                }
                log.warnf("Vault request exhausted retries after transport error. operation=%s path=%s error=%s attempts=%d",
                        operation, path, e.getClass().getSimpleName(), maxAttempts);
                throw VaultErrorMapper.mapTransportFailure(operation, path, e);
            }
        }
        throw new IllegalStateException("Vault retry loop exited without a result");
    }

    private static void sleep(long delayMs) {
        if (delayMs <= 0) {
            return;
        }
        try {
            Thread.sleep(delayMs);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private void logMappingFailure(VaultException e) {
        log.warnf("Vault request failed. operation=%s path=%s status=%d reason=%s",
                e.getOperation(), e.getVaultPath(), e.getHttpStatus(), e.getClass().getSimpleName());
    }

    static String secretUrl(HashicorpVaultConfig config, String vaultKey) {
        return VaultPathResolver.secretUrl(config, vaultKey);
    }

    static String deleteUrl(HashicorpVaultConfig config, String vaultKey) {
        return VaultPathResolver.deleteUrl(config, vaultKey);
    }

    SimpleHttpRequest applyVaultHeaders(SimpleHttpRequest request, String token) {
        if (token != null && !token.isEmpty()) {
            request = request.header("X-Vault-Token", token);
        }
        String namespace = config.getNamespace();
        if (namespace != null && !namespace.isEmpty()) {
            request = request.header("X-Vault-Namespace", namespace);
        }
        return request;
    }

    static Map<String, Object> writeBody(HashicorpVaultConfig config, String secret) {
        if (config.getKvVersion() == 2) {
            return Map.of("data", Map.of(config.getKvField(), secret));
        }
        return Map.of(config.getKvField(), secret);
    }

    static String extractField(JsonNode root, int kvVersion, String field) {
        if (root == null || field == null) {
            return null;
        }
        JsonNode data = kvVersion == 2 ? root.path("data").path("data") : root.path("data");
        JsonNode value = data.get(field);
        if (value == null || value.isMissingNode() || value.isNull()) {
            return null;
        }
        return value.asText();
    }

    /** Vault paths never contain secret values, only mount/realm/key segments: safe to log. */
    private static String safePath(String vaultKeyOrPath) {
        return vaultKeyOrPath == null ? "-" : vaultKeyOrPath;
    }

    private static String stripLeadingSlash(String path) {
        if (path == null || path.isEmpty()) {
            return path;
        }
        return path.charAt(0) == '/' ? path.substring(1) : path;
    }

    public record SecretLookup(int status, String value) {
        public boolean isForbidden() {
            return status == 403;
        }

        public boolean found() {
            return value != null && !value.isEmpty();
        }
    }

    public record WriteResult(int status) {
        public boolean success() {
            return status >= 200 && status < 300;
        }

        public boolean isForbidden() {
            return status == 403;
        }
    }

    public record DeleteResult(int status) {
        public boolean success() {
            return (status >= 200 && status < 300) || status == 404;
        }

        public boolean isForbidden() {
            return status == 403;
        }
    }

    public record HealthStatus(boolean healthy, int httpStatus, String error) {
    }
}
