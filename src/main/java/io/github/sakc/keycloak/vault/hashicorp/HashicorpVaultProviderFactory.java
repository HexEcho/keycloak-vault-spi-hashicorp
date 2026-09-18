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
import io.github.sakc.keycloak.vault.hashicorp.auth.StaticTokenProvider;
import io.github.sakc.keycloak.vault.hashicorp.auth.VaultTokenProvider;
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

    @Override
    public VaultProvider create(KeycloakSession session) {
        if (vaultConfig == null || client == null || tokenProvider == null) {
            log.debug("HashiCorp vault provider is not initialized");
            return null;
        }
        return new HashicorpVaultProvider(getRealmName(session), keyResolvers, session, vaultConfig, client,
                tokenProvider);
    }

    @Override
    public void init(Config.Scope config) {
        super.init(config);
        this.vaultConfig = HashicorpVaultConfig.from(config);
        this.client = new HashicorpVaultClient(vaultConfig);
        this.tokenProvider = createTokenProvider(config, vaultConfig, client);
        log.infof("HashiCorp vault provider initialized. authMethod=%s url=%s namespace=%s kvMount=%s kvVersion=%d",
                vaultConfig.getAuthMethod(), vaultConfig.getUrl(),
                vaultConfig.getNamespace() == null ? "-" : vaultConfig.getNamespace(),
                vaultConfig.getKvMount(), vaultConfig.getKvVersion());
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public void close() {
        if (tokenProvider != null) {
            tokenProvider.close();
            tokenProvider = null;
        }
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

    public String resolveKey(String realm, String key) {
        if (keyResolvers != null && !keyResolvers.isEmpty()) {
            return keyResolvers.get(0).apply(realm, key);
        }
        return realm + "_" + key;
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
                        HashicorpVaultConfig.AUTH_CERT))
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
                .name("cache-ttl")
                .label("Cache TTL (ms)")
                .helpText("Infinispan entry lifespan in milliseconds. Use 0 or negative to disable caching.")
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue(String.valueOf(HashicorpVaultConfig.DEFAULT_CACHE_TTL_MS))
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
                log.error("AppRole auth-method selected but approle-role-id or approle-secret-id is not configured.");
            }
            return new AppRoleTokenProvider(client, mountPath, roleId, secretId);
        }
        if (HashicorpVaultConfig.AUTH_CERT.equals(vaultConfig.getAuthMethod())) {
            String certName = config.get("cert-name");
            String mountPath = config.get("cert-mount-path", "cert");
            return new CertTokenProvider(client, mountPath, certName);
        }
        String token = config.get("token");
        if (token == null || token.isBlank()) {
            log.warn("Vault token is not configured. Lookups will fail until spi-vault--hashicorp--token is set.");
        }
        return new StaticTokenProvider(token);
    }
}
