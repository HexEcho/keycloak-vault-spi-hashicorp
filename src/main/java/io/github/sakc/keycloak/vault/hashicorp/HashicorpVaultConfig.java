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

import io.github.sakc.keycloak.vault.hashicorp.exception.VaultConfigurationException;
import org.jboss.logging.Logger;
import org.keycloak.Config;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Locale;
import java.util.Set;

/**
 * Immutable runtime configuration for the HashiCorp vault provider.
 * Built once in {@link HashicorpVaultProviderFactory#init(Config.Scope)}.
 */
public final class HashicorpVaultConfig {

    private static final Logger log = Logger.getLogger(HashicorpVaultConfig.class);

    public static final String DEFAULT_URL = "http://127.0.0.1:8200";
    public static final String DEFAULT_KV_MOUNT = "secret";
    public static final String DEFAULT_KV_FIELD = "value";
    public static final int DEFAULT_KV_VERSION = 2;
    public static final long DEFAULT_CACHE_TTL_MS = 300_000L;
    public static final int DEFAULT_CACHE_MAX_ENTRIES = 10_000;

    public static final long DEFAULT_CONNECT_TIMEOUT_MS = 2_000L;
    public static final long DEFAULT_READ_TIMEOUT_MS = 5_000L;
    public static final long DEFAULT_REQUEST_TIMEOUT_MS = 5_000L;

    public static final int DEFAULT_RETRY_MAX_ATTEMPTS = 4;
    public static final long DEFAULT_RETRY_INITIAL_DELAY_MS = 100L;
    public static final long DEFAULT_RETRY_MAX_DELAY_MS = 1_000L;

    public static final boolean DEFAULT_HEALTH_CHECK_ENABLED = false;
    public static final long DEFAULT_HEALTH_CHECK_INTERVAL_MS = 30_000L;

    public static final String AUTH_TOKEN = "token";
    public static final String AUTH_APPROLE = "approle";
    public static final String AUTH_CERT = "cert";
    public static final String AUTH_KUBERNETES = "kubernetes";
    public static final String DEFAULT_KUBERNETES_MOUNT_PATH = "kubernetes";
    public static final String DEFAULT_KUBERNETES_JWT_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/token";

    private static final Set<String> CERT_ALIASES = Set.of("cert", "certificate", "tls", "tls-cert");

    private final String url;
    private final String authMethod;
    private final String namespace;
    private final String kvMount;
    private final int kvVersion;
    private final String kvField;
    private final Integer kvReadVersion;
    private final boolean cacheEnabled;
    private final long cacheTtlMs;
    private final int cacheMaxEntries;
    private final String managedSecretPrefix;
    private final long connectTimeoutMs;
    private final long readTimeoutMs;
    private final long requestTimeoutMs;
    private final int retryMaxAttempts;
    private final long retryInitialDelayMs;
    private final long retryMaxDelayMs;
    private final boolean healthCheckEnabled;
    private final long healthCheckIntervalMs;

    private HashicorpVaultConfig(String url, String authMethod, String namespace, String kvMount, int kvVersion,
                                  String kvField, Integer kvReadVersion, boolean cacheEnabled, long cacheTtlMs,
                                  int cacheMaxEntries, String managedSecretPrefix,
                                  long connectTimeoutMs, long readTimeoutMs, long requestTimeoutMs,
                                  int retryMaxAttempts, long retryInitialDelayMs, long retryMaxDelayMs,
                                  boolean healthCheckEnabled, long healthCheckIntervalMs) {
        this.url = url;
        this.authMethod = authMethod;
        this.namespace = namespace;
        this.kvMount = kvMount;
        this.kvVersion = kvVersion;
        this.kvField = kvField;
        this.kvReadVersion = kvReadVersion;
        this.cacheEnabled = cacheEnabled;
        this.cacheTtlMs = cacheTtlMs;
        this.cacheMaxEntries = cacheMaxEntries;
        this.managedSecretPrefix = managedSecretPrefix;
        this.connectTimeoutMs = connectTimeoutMs;
        this.readTimeoutMs = readTimeoutMs;
        this.requestTimeoutMs = requestTimeoutMs;
        this.retryMaxAttempts = retryMaxAttempts;
        this.retryInitialDelayMs = retryInitialDelayMs;
        this.retryMaxDelayMs = retryMaxDelayMs;
        this.healthCheckEnabled = healthCheckEnabled;
        this.healthCheckIntervalMs = healthCheckIntervalMs;
    }

    public static HashicorpVaultConfig from(Config.Scope config) {
        String url = trimTrailingSlash(config.get("url", DEFAULT_URL));
        validateUrl(url);
        String authMethod = normalizeAuthMethod(config.get("auth-method", AUTH_TOKEN));
        String namespace = blankToNull(config.get("namespace"));
        String kvMount = stripSlashes(config.get("kv-mount", DEFAULT_KV_MOUNT));
        int kvVersion = config.getInt("kv-version", DEFAULT_KV_VERSION);
        if (kvVersion != 1 && kvVersion != 2) {
            log.warnf("Unsupported kv-version %d; using %d.", kvVersion, DEFAULT_KV_VERSION);
            kvVersion = DEFAULT_KV_VERSION;
        }
        String kvField = config.get("kv-field", DEFAULT_KV_FIELD);
        Integer kvReadVersion = optionalPositiveInt(config.getInt("kv-read-version", 0), "kv-read-version");
        if (kvVersion != 2 && kvReadVersion != null) {
            log.warn("kv-read-version applies only to KV v2; ignoring it for KV v1.");
            kvReadVersion = null;
        }
        boolean cacheEnabled = config.getBoolean("cache-enabled", true);
        long cacheTtlMs = config.getLong("cache-ttl", DEFAULT_CACHE_TTL_MS);
        if (cacheTtlMs < 0) {
            log.warnf("cache-ttl must be >= 0; using %d.", DEFAULT_CACHE_TTL_MS);
            cacheTtlMs = DEFAULT_CACHE_TTL_MS;
        }
        int cacheMaxEntries = config.getInt("cache-max-entries", DEFAULT_CACHE_MAX_ENTRIES);
        if (cacheMaxEntries < 1) {
            log.warnf("cache-max-entries must be >= 1; using %d.", DEFAULT_CACHE_MAX_ENTRIES);
            cacheMaxEntries = DEFAULT_CACHE_MAX_ENTRIES;
        }
        String managedSecretPrefix = blankToNull(config.get("managed-secret-prefix"));

        long connectTimeoutMs = positiveOrDefault(config.getLong("connect-timeout-ms", DEFAULT_CONNECT_TIMEOUT_MS),
                DEFAULT_CONNECT_TIMEOUT_MS, "connect-timeout-ms");
        long readTimeoutMs = positiveOrDefault(config.getLong("read-timeout-ms", DEFAULT_READ_TIMEOUT_MS),
                DEFAULT_READ_TIMEOUT_MS, "read-timeout-ms");
        long requestTimeoutMs = positiveOrDefault(config.getLong("request-timeout-ms", DEFAULT_REQUEST_TIMEOUT_MS),
                DEFAULT_REQUEST_TIMEOUT_MS, "request-timeout-ms");

        int retryMaxAttempts = config.getInt("retry-max-attempts", DEFAULT_RETRY_MAX_ATTEMPTS);
        if (retryMaxAttempts < 1) {
            log.warnf("retry-max-attempts must be >= 1; using %d.", DEFAULT_RETRY_MAX_ATTEMPTS);
            retryMaxAttempts = DEFAULT_RETRY_MAX_ATTEMPTS;
        }
        long retryInitialDelayMs = positiveOrDefault(config.getLong("retry-initial-delay-ms", DEFAULT_RETRY_INITIAL_DELAY_MS),
                DEFAULT_RETRY_INITIAL_DELAY_MS, "retry-initial-delay-ms");
        long retryMaxDelayMs = positiveOrDefault(config.getLong("retry-max-delay-ms", DEFAULT_RETRY_MAX_DELAY_MS),
                DEFAULT_RETRY_MAX_DELAY_MS, "retry-max-delay-ms");
        boolean healthCheckEnabled = config.getBoolean("health-check-enabled", DEFAULT_HEALTH_CHECK_ENABLED);
        long healthCheckIntervalMs = positiveOrDefault(config.getLong("health-check-interval-ms", DEFAULT_HEALTH_CHECK_INTERVAL_MS),
                DEFAULT_HEALTH_CHECK_INTERVAL_MS, "health-check-interval-ms");

        return new HashicorpVaultConfig(url, authMethod, namespace, kvMount, kvVersion, kvField, kvReadVersion,
                cacheEnabled, cacheTtlMs, cacheMaxEntries, managedSecretPrefix,
                connectTimeoutMs, readTimeoutMs, requestTimeoutMs, retryMaxAttempts,
                retryInitialDelayMs, retryMaxDelayMs, healthCheckEnabled, healthCheckIntervalMs);
    }
/**
     * Rejects a malformed Vault URL at startup instead of letting every subsequent request fail
     * with an opaque connection error. Must be an absolute {@code http}/{@code https} URL with a
     * host; Vault does not serve KV traffic over any other scheme.
     */
    private static void validateUrl(String url) {
        if (url == null || url.isBlank()) {
            throw new VaultConfigurationException("Vault url must not be blank.");
        }
        URI uri;
        try {
            uri = new URI(url);
        } catch (URISyntaxException e) {
            throw new VaultConfigurationException("Vault url '" + url + "' is not a valid URI: " + e.getMessage());
        }
        String scheme = uri.getScheme();
        if (scheme == null || !(scheme.equalsIgnoreCase("http") || scheme.equalsIgnoreCase("https"))) {
            throw new VaultConfigurationException(
                    "Vault url '" + url + "' must use the http or https scheme.");
        }
        if (uri.getHost() == null || uri.getHost().isBlank()) {
            throw new VaultConfigurationException("Vault url '" + url + "' must include a host.");
        }
    }

    
    private static Integer optionalPositiveInt(int value, String propertyName) {
        if (value == 0) {
            return null;
        }
        if (value < 0) {
            log.warnf("%s must be > 0 when set; ignoring it.", propertyName);
            return null;
        }
        return value;
    }

    private static long positiveOrDefault(long value, long defaultValue, String propertyName) {
        if (value <= 0) {
            log.warnf("%s must be > 0; using %d.", propertyName, defaultValue);
            return defaultValue;
        }
        return value;
    }

    public String getUrl() {
        return url;
    }

    public String getAuthMethod() {
        return authMethod;
    }

    public String getNamespace() {
        return namespace;
    }

    public String getKvMount() {
        return kvMount;
    }

    public int getKvVersion() {
        return kvVersion;
    }

    public String getKvField() {
        return kvField;
    }

    public Integer getKvReadVersion() {
        return kvReadVersion;
    }

    public long getCacheTtlMs() {
        return cacheTtlMs;
    }

    public boolean cacheEnabled() {
        return cacheEnabled && cacheTtlMs > 0;
    }

    public int getCacheMaxEntries() {
        return cacheMaxEntries;
    }

    /**
     * Optional sub-path (for example {@code managed}) that separates confidential-client
     * secrets this SPI creates and owns from secrets an operator manages directly in Vault.
     * {@code null} preserves the existing (pre-hardening) path layout for backward compatibility.
     */
    public String getManagedSecretPrefix() {
        return managedSecretPrefix;
    }

    public long getConnectTimeoutMs() {
        return connectTimeoutMs;
    }

    public long getReadTimeoutMs() {
        return readTimeoutMs;
    }

    public long getRequestTimeoutMs() {
        return requestTimeoutMs;
    }

    public int getRetryMaxAttempts() {
        return retryMaxAttempts;
    }

    public long getRetryInitialDelayMs() {
        return retryInitialDelayMs;
    }

    public long getRetryMaxDelayMs() {
        return retryMaxDelayMs;
    }

    public boolean isHealthCheckEnabled() {
        return healthCheckEnabled;
    }

    public long getHealthCheckIntervalMs() {
        return healthCheckIntervalMs;
    }

    static String normalizeAuthMethod(String authMethod) {
        if (authMethod == null || authMethod.isBlank()) {
            return AUTH_TOKEN;
        }
        String normalized = authMethod.trim().toLowerCase(Locale.ROOT);
        if (AUTH_TOKEN.equals(normalized) || AUTH_APPROLE.equals(normalized) || AUTH_KUBERNETES.equals(normalized)) {
            return normalized;
        }
        if (CERT_ALIASES.contains(normalized)) {
            return AUTH_CERT;
        }
        log.warnf("Unknown auth-method '%s'; falling back to token.", authMethod);
        return AUTH_TOKEN;
    }

    static String trimTrailingSlash(String value) {
        if (value == null || value.isEmpty()) {
            return value;
        }
        int end = value.length();
        while (end > 0 && value.charAt(end - 1) == '/') {
            end--;
        }
        return value.substring(0, end);
    }

    static String stripSlashes(String value) {
        if (value == null) {
            return DEFAULT_KV_MOUNT;
        }
        int start = 0;
        int end = value.length();
        while (start < end && value.charAt(start) == '/') {
            start++;
        }
        while (end > start && value.charAt(end - 1) == '/') {
            end--;
        }
        return start == 0 && end == value.length() ? value : value.substring(start, end);
    }

    static String blankToNull(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }
}
