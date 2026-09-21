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

import io.github.sakc.keycloak.vault.hashicorp.auth.AppRoleTokenProvider;
import io.github.sakc.keycloak.vault.hashicorp.auth.CertTokenProvider;
import io.github.sakc.keycloak.vault.hashicorp.auth.KubernetesTokenProvider;
import io.github.sakc.keycloak.vault.hashicorp.auth.StaticTokenProvider;
import io.github.sakc.keycloak.vault.hashicorp.auth.VaultTokenProvider;
import io.github.sakc.keycloak.vault.hashicorp.exception.VaultConfigurationException;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;
import org.keycloak.vault.AbstractVaultProviderFactory;
import org.keycloak.vault.VaultProvider;

import java.util.List;

/**
 * Factory for the HashiCorp {@link VaultProvider}. Instantiated once by Keycloak.
 */
public class HashicorpVaultProviderFactory extends AbstractVaultProviderFactory {

    private static final Logger log = Logger.getLogger(HashicorpVaultProviderFactory.class);

    public static final String PROVIDER_ID = "hashicorp";

    private HashicorpVaultConfig vaultConfig;
    private HashicorpVaultClient client;
    private VaultTokenProvider tokenProvider;
    private VaultSecretService secretService;
    private VaultHealthChecker healthChecker;

    @Override
    public VaultProvider create(KeycloakSession session) {
        if (vaultConfig == null || client == null || tokenProvider == null) {
            log.debug("HashiCorp vault provider is not initialized");
            return null;
        }
        return new HashicorpVaultProvider(getRealmName(session), keyResolvers, session, vaultConfig, secretService);
    }

    @Override
    public void init(Config.Scope config) {
        super.init(config);
        this.vaultConfig = HashicorpVaultConfig.from(config);
        this.client = new HashicorpVaultClient(vaultConfig);
        this.tokenProvider = createTokenProvider(config, vaultConfig, client);
        this.secretService = new VaultSecretService(client, tokenProvider);
        log.infof("HashiCorp vault provider initialized. authMethod=%s url=%s namespace=%s kvMount=%s kvVersion=%d "
                        + "connectTimeoutMs=%d readTimeoutMs=%d retryMaxAttempts=%d healthCheckEnabled=%s",
                vaultConfig.getAuthMethod(), vaultConfig.getUrl(),
                vaultConfig.getNamespace() == null ? "-" : vaultConfig.getNamespace(),
                vaultConfig.getKvMount(), vaultConfig.getKvVersion(),
                vaultConfig.getConnectTimeoutMs(), vaultConfig.getReadTimeoutMs(), vaultConfig.getRetryMaxAttempts(),
                vaultConfig.isHealthCheckEnabled());
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        if (vaultConfig != null && vaultConfig.isHealthCheckEnabled() && client != null) {
            healthChecker = VaultHealthChecker.start(factory, client, vaultConfig);
        }
    }

    @Override
    public void close() {
        if (healthChecker != null) {
            healthChecker.close();
            healthChecker = null;
        }
        if (tokenProvider != null) {
            tokenProvider.close();
            tokenProvider = null;
        }
        secretService = null;
        client = null;
        vaultConfig = null;
    }

    public HashicorpVaultConfig vaultConfig() {
        return vaultConfig;
    }

    public HashicorpVaultClient vaultHttp() {
        return client;
    }

    public VaultTokenProvider tokenProvider() {
        return tokenProvider;
    }

    public VaultSecretService vaultSecretService() {
        return secretService;
    }

    public String resolveKey(String realm, String key) {
        if (keyResolvers != null && !keyResolvers.isEmpty()) {
            return keyResolvers.get(0).apply(realm, key);
        }
        return realm + "_" + key;
    }

    /**
     * Deterministic, realm-isolated path for a secret this SPI creates and owns, kept apart from
     * externally managed Vault entries. Returns {@code null} (caller falls back to {@link #resolveKey})
     * when {@code managed-secret-prefix} is not configured, preserving the pre-hardening path layout.
     */
    public String resolveManagedKey(String realm, String key) {
        String prefix = vaultConfig == null ? null : vaultConfig.getManagedSecretPrefix();
        if (prefix == null) {
            return null;
        }
        return VaultPathResolver.managedKey(realm, prefix, key);
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public List<ProviderConfigProperty> getConfigMetadata() {
        return ProviderConfigurationBuilder.create()
                .property()
                .name("url")
                .label("Vault URL")
                .helpText("Base URL of the HashiCorp Vault server.")
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue(HashicorpVaultConfig.DEFAULT_URL)
                .add()
                .property()
                .name("auth-method")
                .label("Auth method")
                .helpText("Vault authentication method.")
                .type(ProviderConfigProperty.LIST_TYPE)
                .options(List.of(HashicorpVaultConfig.AUTH_TOKEN, HashicorpVaultConfig.AUTH_APPROLE,
                        HashicorpVaultConfig.AUTH_CERT, HashicorpVaultConfig.AUTH_KUBERNETES))
                .defaultValue(HashicorpVaultConfig.AUTH_TOKEN)
                .add()
                .property()
                .name("namespace")
                .label("Vault namespace")
                .helpText("Vault Enterprise namespace sent as X-Vault-Namespace on every request. Nested namespaces use parent/child.")
                .type(ProviderConfigProperty.STRING_TYPE)
                .add()
                .property()
                .name("token")
                .label("Token")
                .helpText("Static Vault token. Used when auth-method=token.")
                .type(ProviderConfigProperty.STRING_TYPE)
                .secret(true)
                .add()
                .property()
                .name("approle-role-id")
                .label("AppRole role id")
                .helpText("AppRole role-id. Used when auth-method=approle.")
                .type(ProviderConfigProperty.STRING_TYPE)
                .add()
                .property()
                .name("approle-secret-id")
                .label("AppRole secret id")
                .helpText("AppRole secret-id. Used when auth-method=approle.")
                .type(ProviderConfigProperty.STRING_TYPE)
                .secret(true)
                .add()
                .property()
                .name("approle-mount-path")
                .label("AppRole mount path")
                .helpText("Vault mount path for the AppRole auth method.")
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue("approle")
                .add()
                .property()
                .name("cert-name")
                .label("Certificate role name")
                .helpText("Optional Vault cert auth role name. Used when auth-method=cert.")
                .type(ProviderConfigProperty.STRING_TYPE)
                .add()
                .property()
                .name("cert-mount-path")
                .label("Certificate mount path")
                .helpText("Vault mount path for the TLS certificate auth method.")
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue("cert")
                .add()
                .property()
                .name("kubernetes-role")
                .label("Kubernetes role")
                .helpText("Vault Kubernetes auth role. Used when auth-method=kubernetes.")
                .type(ProviderConfigProperty.STRING_TYPE)
                .add()
                .property()
                .name("kubernetes-mount-path")
                .label("Kubernetes mount path")
                .helpText("Vault mount path for the Kubernetes auth method.")
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue(HashicorpVaultConfig.DEFAULT_KUBERNETES_MOUNT_PATH)
                .add()
                .property()
                .name("kubernetes-jwt-path")
                .label("Kubernetes JWT path")
                .helpText("Path to the service account JWT file, read fresh on every Vault login and never logged or cached to disk.")
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue(HashicorpVaultConfig.DEFAULT_KUBERNETES_JWT_PATH)
                .add()
                .property()
                .name("managed-secret-prefix")
                .label("Managed secret prefix")
                .helpText("Optional sub-path (for example 'managed') separating confidential-client secrets this SPI "
                        + "writes/deletes from secrets an operator manages directly in Vault. Unset preserves the "
                        + "existing path layout.")
                .type(ProviderConfigProperty.STRING_TYPE)
                .add()
                .property()
                .name("kv-mount")
                .label("KV mount")
                .helpText("KV secrets engine mount path.")
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue(HashicorpVaultConfig.DEFAULT_KV_MOUNT)
                .add()
                .property()
                .name("kv-version")
                .label("KV version")
                .helpText("KV secrets engine version (1 or 2).")
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue(String.valueOf(HashicorpVaultConfig.DEFAULT_KV_VERSION))
                .add()
                .property()
                .name("kv-field")
                .label("KV field")
                .helpText("Field name inside the KV data map that holds the secret.")
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue(HashicorpVaultConfig.DEFAULT_KV_FIELD)
                .add()
                .property()
                .name("kv-read-version")
                .label("KV v2 read version")
                .helpText("Optional immutable KV v2 version to read. Unset reads the latest version; KV v1 ignores this setting.")
                .type(ProviderConfigProperty.STRING_TYPE)
                .add()
                .property()
                .name("cache-enabled")
                .label("Cache enabled")
                .helpText("Enables the local Infinispan cache for successful Vault reads.")
                .type(ProviderConfigProperty.BOOLEAN_TYPE)
                .defaultValue("true")
                .add()
                .property()
                .name("cache-ttl")
                .label("Cache TTL (ms)")
                .helpText("Infinispan entry lifespan in milliseconds. Use 0 to disable caching.")
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue(String.valueOf(HashicorpVaultConfig.DEFAULT_CACHE_TTL_MS))
                .add()
                .property()
                .name("cache-max-entries")
                .label("Cache maximum entries")
                .helpText("Maximum entries in the node-local Infinispan cache.")
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue(String.valueOf(HashicorpVaultConfig.DEFAULT_CACHE_MAX_ENTRIES))
                .add()
                .property()
                .name("connect-timeout-ms")
                .label("Connect timeout (ms)")
                .helpText("Maximum time to establish a TCP connection to Vault before failing fast.")
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue(String.valueOf(HashicorpVaultConfig.DEFAULT_CONNECT_TIMEOUT_MS))
                .add()
                .property()
                .name("read-timeout-ms")
                .label("Read timeout (ms)")
                .helpText("Maximum time to wait for data on an established connection to Vault.")
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue(String.valueOf(HashicorpVaultConfig.DEFAULT_READ_TIMEOUT_MS))
                .add()
                .property()
                .name("request-timeout-ms")
                .label("Request timeout (ms)")
                .helpText("Maximum time to wait for a connection to become available from the pool.")
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue(String.valueOf(HashicorpVaultConfig.DEFAULT_REQUEST_TIMEOUT_MS))
                .add()
                .property()
                .name("retry-max-attempts")
                .label("Retry max attempts")
                .helpText("Maximum number of attempts (including the first) for a Vault request. 429/500/502/503/504 "
                        + "and connection failures are retried; 400/401/403/404 are never retried.")
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue(String.valueOf(HashicorpVaultConfig.DEFAULT_RETRY_MAX_ATTEMPTS))
                .add()
                .property()
                .name("retry-initial-delay-ms")
                .label("Retry initial delay (ms)")
                .helpText("Backoff delay before the second attempt. Doubles on each subsequent attempt up to retry-max-delay-ms, with +/-20% jitter.")
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue(String.valueOf(HashicorpVaultConfig.DEFAULT_RETRY_INITIAL_DELAY_MS))
                .add()
                .property()
                .name("retry-max-delay-ms")
                .label("Retry max delay (ms)")
                .helpText("Upper bound on the exponential backoff delay between retries.")
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue(String.valueOf(HashicorpVaultConfig.DEFAULT_RETRY_MAX_DELAY_MS))
                .add()
                .property()
                .name("health-check-enabled")
                .label("Health check enabled")
                .helpText("Poll GET /v1/sys/health on a background thread for operational diagnostics. Never runs on the secret-lookup path.")
                .type(ProviderConfigProperty.BOOLEAN_TYPE)
                .defaultValue(String.valueOf(HashicorpVaultConfig.DEFAULT_HEALTH_CHECK_ENABLED))
                .add()
                .property()
                .name("health-check-interval-ms")
                .label("Health check interval (ms)")
                .helpText("Delay between background Vault health checks. Only used when health-check-enabled=true.")
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue(String.valueOf(HashicorpVaultConfig.DEFAULT_HEALTH_CHECK_INTERVAL_MS))
                .add()
                .property()
                .name(KEY_RESOLVERS)
                .label("Key resolvers")
                .helpText("Comma-separated Keycloak vault key resolvers (default REALM_UNDERSCORE_KEY).")
                .type(ProviderConfigProperty.STRING_TYPE)
                .add()
                .build();
    }

    private static VaultTokenProvider createTokenProvider(Config.Scope config, HashicorpVaultConfig vaultConfig,
                                                          HashicorpVaultClient client) {
        if (HashicorpVaultConfig.AUTH_APPROLE.equals(vaultConfig.getAuthMethod())) {
            String roleId = config.get("approle-role-id");
            String secretId = config.get("approle-secret-id");
            String mountPath = config.get("approle-mount-path", "approle");
            if (roleId == null || roleId.isBlank() || secretId == null || secretId.isBlank()) {
                throw new VaultConfigurationException(
                        "auth-method=approle requires both approle-role-id and approle-secret-id to be set.");
            }
            return new AppRoleTokenProvider(client, mountPath, roleId, secretId);
        }
        if (HashicorpVaultConfig.AUTH_CERT.equals(vaultConfig.getAuthMethod())) {
            String certName = config.get("cert-name");
            String mountPath = config.get("cert-mount-path", "cert");
            return new CertTokenProvider(client, mountPath, certName);
        }
        if (HashicorpVaultConfig.AUTH_KUBERNETES.equals(vaultConfig.getAuthMethod())) {
            String role = config.get("kubernetes-role");
            String mountPath = config.get("kubernetes-mount-path", HashicorpVaultConfig.DEFAULT_KUBERNETES_MOUNT_PATH);
            String jwtPath = config.get("kubernetes-jwt-path", HashicorpVaultConfig.DEFAULT_KUBERNETES_JWT_PATH);
            if (role == null || role.isBlank()) {
                throw new VaultConfigurationException(
                        "auth-method=kubernetes requires kubernetes-role to be set.");
            }
            return KubernetesTokenProvider.forJwtFile(client, mountPath, role, jwtPath);
        }
        String token = config.get("token");
        if (token == null || token.isBlank()) {
            log.warn("Vault token is not configured. Lookups will fail until spi-vault--hashicorp--token is set.");
        }
        return new StaticTokenProvider(token);
    }
}
