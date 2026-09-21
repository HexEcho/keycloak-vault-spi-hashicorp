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
package io.github.sakc.keycloak.vault.hashicorp.events;

import io.github.sakc.keycloak.vault.hashicorp.HashicorpVaultClient;
import io.github.sakc.keycloak.vault.hashicorp.HashicorpVaultConfig;
import io.github.sakc.keycloak.vault.hashicorp.HashicorpVaultExpressions;
import io.github.sakc.keycloak.vault.hashicorp.HashicorpVaultProvider;
import io.github.sakc.keycloak.vault.hashicorp.HashicorpVaultProviderFactory;
import io.github.sakc.keycloak.vault.hashicorp.VaultSecretService;
import io.github.sakc.keycloak.vault.hashicorp.cache.HashicorpVaultCacheKey;
import io.github.sakc.keycloak.vault.hashicorp.cache.HashicorpVaultCaches;
import org.infinispan.Cache;
import org.jboss.logging.Logger;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.events.admin.OperationType;
import org.keycloak.events.admin.ResourceType;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.vault.VaultProvider;


/**
 * Writes a generated client secret to HashiCorp KV and stores {@code ${vault.clientId}} in Keycloak.
 */
public final class ClientSecretVaultSync {

    private static final Logger log = Logger.getLogger(ClientSecretVaultSync.class);
    private static final String SYNCING = ClientSecretVaultSync.class.getName() + ".syncing";

    private ClientSecretVaultSync() {
    }

    public static HashicorpVaultProviderFactory vaultFactory(KeycloakSession session) {
        if (session == null) {
            return null;
        }
        return (HashicorpVaultProviderFactory) session.getKeycloakSessionFactory()
                .getProviderFactory(VaultProvider.class, HashicorpVaultProviderFactory.PROVIDER_ID);
    }

    public static boolean shouldSync(ClientModel client) {
        if (client == null || client.isPublicClient() || client.isBearerOnly()) {
            return false;
        }
        String clientId = client.getClientId();
        if (clientId == null || clientId.isBlank() || clientId.indexOf('}') >= 0) {
            return false;
        }
        String secret = client.getSecret();
        return secret != null && !secret.isBlank() && !HashicorpVaultExpressions.isExpression(secret);
    }

    public static boolean isClientSecretAdminEvent(AdminEvent event) {
        if (event == null) {
            return false;
        }
        OperationType operation = event.getOperationType();
        if (operation == OperationType.ACTION && isClientSecretPath(event.getResourcePath())) {
            return true;
        }
        if (event.getResourceType() != ResourceType.CLIENT) {
            return false;
        }
        return operation == OperationType.CREATE || operation == OperationType.UPDATE;
    }

    public static boolean isClientDeletionAdminEvent(AdminEvent event) {
        return event != null
                && event.getResourceType() == ResourceType.CLIENT
                && event.getOperationType() == OperationType.DELETE;
    }

    public static String clientUuidFromPath(String resourcePath) {
        if (resourcePath == null || resourcePath.isEmpty()) {
            return null;
        }
        String[] parts = resourcePath.split("/");
        for (int i = 0; i < parts.length; i++) {
            if ("clients".equals(parts[i]) && i + 1 < parts.length && !parts[i + 1].isEmpty()) {
                return parts[i + 1];
            }
        }
        return null;
    }

    public static boolean isClientSecretPath(String resourcePath) {
        return resourcePath != null && resourcePath.contains("client-secret") && !resourcePath.contains("rotated");
    }

    public static void sync(KeycloakSession session, ClientModel client) {
        sync(session, vaultFactory(session), client);
    }

    public static void sync(KeycloakSession session, HashicorpVaultProviderFactory factory, ClientModel client) {
        if (session == null || factory == null || !shouldSync(client)) {
            return;
        }
        if (Boolean.TRUE.equals(session.getAttribute(SYNCING))) {
            return;
        }
        HashicorpVaultConfig config = factory.vaultConfig();
        VaultSecretService secretService = factory.vaultSecretService();
        if (config == null || secretService == null) {
            return;
        }
        RealmModel realm = client.getRealm();
        if (realm == null) {
            return;
        }
        String vaultKey = resolveVaultKey(factory, realm.getName(), client.getClientId());
        if (vaultKey == null || !HashicorpVaultProvider.isSafeResolvedKey(vaultKey)) {
            log.warn("Refusing to write client secret for an unsafe or unresolvable vault key.");
            return;
        }

        session.setAttribute(SYNCING, Boolean.TRUE);
        try {
            String secret = client.getSecret();
            HashicorpVaultClient.WriteResult result = secretService.writeSecret(session, vaultKey, secret);
            if (!result.success()) {
                return;
            }
            client.setSecret(HashicorpVaultExpressions.pointer(client.getClientId()));
            client.updateClient();
            cacheRemove(session, config, realm.getName(), vaultKey);
            log.infof("Stored client secret in HashiCorp Vault at key %s and set Keycloak secret to %s",
                    vaultKey, HashicorpVaultExpressions.pointer(client.getClientId()));
        } finally {
            session.removeAttribute(SYNCING);
        }
    }

    public static void delete(KeycloakSession session, ClientModel client) {
        delete(session, vaultFactory(session), client);
    }

    public static void delete(KeycloakSession session, HashicorpVaultProviderFactory factory, ClientModel client) {
        if (session == null || factory == null || client == null || client.isPublicClient() || client.isBearerOnly()) {
            return;
        }
        String clientId = client.getClientId();
        if (clientId == null || clientId.isBlank()
                || !HashicorpVaultExpressions.pointer(clientId).equals(client.getSecret())) {
            return;
        }

        HashicorpVaultConfig config = factory.vaultConfig();
        VaultSecretService secretService = factory.vaultSecretService();
        RealmModel realm = client.getRealm();
        if (config == null || secretService == null || realm == null) {
            return;
        }

        String vaultKey = resolveVaultKey(factory, realm.getName(), clientId);
        if (vaultKey == null || !HashicorpVaultProvider.isSafeResolvedKey(vaultKey)) {
            log.warn("Refusing to delete client secret for an unsafe or unresolvable vault key.");
            return;
        }

        HashicorpVaultClient.DeleteResult result = secretService.deleteSecret(session, vaultKey);
        if (result.success()) {
            cacheRemove(session, config, realm.getName(), vaultKey);
            log.infof("Deleted client secret from HashiCorp Vault at key %s", vaultKey);
        } else {
            log.errorf("Failed to delete client secret from Vault for key %s. HTTP %d.", vaultKey, result.status());
        }
    }

    public static void syncFromAdminEvent(KeycloakSession session, AdminEvent event) {
        if (session == null || !isClientSecretAdminEvent(event)) {
            return;
        }
        RealmModel realm = session.realms().getRealm(event.getRealmId());
        if (realm == null) {
            return;
        }
        String clientUuid = clientUuidFromPath(event.getResourcePath());
        if (clientUuid == null) {
            return;
        }
        ClientModel client = session.clients().getClientById(realm, clientUuid);
        sync(session, client);
    }

    /**
     * Resolves the write/delete path for a managed client secret. When {@code managed-secret-prefix}
     * is configured this uses the explicit {@code <realm>/<prefix>/<clientId>} namespace so SPI-managed
     * secrets never collide with, or get treated as, an externally managed Vault entry. Otherwise it
     * falls back to the existing key-resolver path for backward compatibility.
     */
    private static String resolveVaultKey(HashicorpVaultProviderFactory factory, String realmName, String clientId) {
        try {
            String managed = factory.resolveManagedKey(realmName, clientId);
            return managed != null ? managed : factory.resolveKey(realmName, clientId);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    private static void cacheRemove(KeycloakSession session, HashicorpVaultConfig config, String realm, String vaultKey) {
        Cache<String, String> cache = HashicorpVaultCaches.get(session, config);
        if (cache != null) {
            cache.remove(HashicorpVaultCacheKey.forSecret(realm, vaultKey, config).asString());
        }
    }
}
