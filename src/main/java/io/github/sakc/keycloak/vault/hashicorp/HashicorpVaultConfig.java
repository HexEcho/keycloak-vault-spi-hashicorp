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

import org.jboss.logging.Logger;
import org.keycloak.Config;

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
    private final long cacheTtlMs;
    private final String managedSecretPrefix;

    private HashicorpVaultConfig(String url, String authMethod, String namespace, String kvMount, int kvVersion,
                                  String kvField, long cacheTtlMs, String managedSecretPrefix) {
        this.url = url;
        this.authMethod = authMethod;
        this.namespace = namespace;
        this.kvMount = kvMount;
        this.kvVersion = kvVersion;
        this.kvField = kvField;
        this.cacheTtlMs = cacheTtlMs;
        this.managedSecretPrefix = managedSecretPrefix;
    }

    public static HashicorpVaultConfig from(Config.Scope config) {
        String url = trimTrailingSlash(config.get("url", DEFAULT_URL));
        String authMethod = normalizeAuthMethod(config.get("auth-method", AUTH_TOKEN));
        String namespace = blankToNull(config.get("namespace"));
        String kvMount = stripSlashes(config.get("kv-mount", DEFAULT_KV_MOUNT));
        int kvVersion = config.getInt("kv-version", DEFAULT_KV_VERSION);
        if (kvVersion != 1 && kvVersion != 2) {
            log.warnf("Unsupported kv-version %d; using %d.", kvVersion, DEFAULT_KV_VERSION);
            kvVersion = DEFAULT_KV_VERSION;
        }
        String kvField = config.get("kv-field", DEFAULT_KV_FIELD);
        long cacheTtlMs = config.getLong("cache-ttl", DEFAULT_CACHE_TTL_MS);
        String managedSecretPrefix = blankToNull(config.get("managed-secret-prefix"));
        return new HashicorpVaultConfig(url, authMethod, namespace, kvMount, kvVersion, kvField, cacheTtlMs,
                managedSecretPrefix);
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

    public long getCacheTtlMs() {
        return cacheTtlMs;
    }

    public boolean cacheEnabled() {
        return cacheTtlMs > 0;
    }

    /**
     * Optional sub-path (for example {@code managed}) that separates confidential-client
     * secrets this SPI creates and owns from secrets an operator manages directly in Vault.
     * {@code null} preserves the existing (pre-hardening) path layout for backward compatibility.
     */
    public String getManagedSecretPrefix() {
        return managedSecretPrefix;
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
