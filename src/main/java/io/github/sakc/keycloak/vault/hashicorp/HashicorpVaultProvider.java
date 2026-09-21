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

import io.github.sakc.keycloak.vault.hashicorp.cache.HashicorpVaultCaches;
import io.github.sakc.keycloak.vault.hashicorp.cache.HashicorpVaultCacheKey;
import org.infinispan.Cache;
import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.vault.AbstractVaultProvider;
import org.keycloak.vault.DefaultVaultRawSecret;
import org.keycloak.vault.VaultKeyResolver;
import org.keycloak.vault.VaultRawSecret;
 
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

/**
 * Read-only HashiCorp KV vault. Resolves keys already processed by Keycloak key resolvers.
 */
public class HashicorpVaultProvider extends AbstractVaultProvider {

    private static final Logger log = Logger.getLogger(HashicorpVaultProvider.class);
    private static final VaultRawSecret EMPTY = DefaultVaultRawSecret.forBuffer(Optional.empty());
        private static final ConcurrentHashMap<String, CompletableFuture<HashicorpVaultClient.SecretLookup>> IN_FLIGHT_READS =
            new ConcurrentHashMap<>();

        private final String realm;
    private final KeycloakSession session;
    private final HashicorpVaultConfig config;
    private final VaultSecretService secretService;

    public HashicorpVaultProvider(String realm, List<VaultKeyResolver> resolvers, KeycloakSession session,
                                   HashicorpVaultConfig config, VaultSecretService secretService) {
        super(realm, resolvers);
        this.realm = realm;
        this.session = session;
        this.config = config;
        this.secretService = secretService;
    }

    @Override
    protected boolean validate(VaultKeyResolver resolver, String key, String resolvedKey) {
        if (!super.validate(resolver, key, resolvedKey)) {
            return false;
        }
        if (!isSafeResolvedKey(resolvedKey)) {
            log.warnf("Validation failed for resolved vault key %s", resolvedKey);
            return false;
        }
        return true;
    }

    @Override
    protected VaultRawSecret obtainSecretInternal(String vaultKey) {
        String cacheKey = cacheKey(vaultKey);
        if (config.cacheEnabled()) {
            String cached = cacheGet(cacheKey);
            if (cached != null) {
                return wrap(cached);
            }
        }

        HashicorpVaultClient.SecretLookup lookup = readSingleFlight(cacheKey, vaultKey);
        if (!lookup.found()) {
            return EMPTY;
        }
        if (config.cacheEnabled()) {
            cachePut(cacheKey, lookup.value());
        }
        return wrap(lookup.value());
    }

    @Override
    public void close() {
    }

    public static boolean isSafeResolvedKey(String resolvedKey) {
        return VaultPathResolver.isSafeResolvedKey(resolvedKey);
    }

    private HashicorpVaultClient.SecretLookup readSingleFlight(String cacheKey, String vaultKey) {
        CompletableFuture<HashicorpVaultClient.SecretLookup> leader = new CompletableFuture<>();
        CompletableFuture<HashicorpVaultClient.SecretLookup> existing = IN_FLIGHT_READS.putIfAbsent(cacheKey, leader);
        if (existing == null) {
            try {
                HashicorpVaultClient.SecretLookup lookup = secretService.readSecret(session, vaultKey);
                leader.complete(lookup);
                return lookup;
            } catch (RuntimeException e) {
                leader.completeExceptionally(e);
                throw e;
            } finally {
                IN_FLIGHT_READS.remove(cacheKey, leader);
            }
        }
        return existing.join();
    }

    private String cacheKey(String vaultKey) {
        return HashicorpVaultCacheKey.forSecret(realm, vaultKey, config).asString();
    }

    private String cacheGet(String cacheKey) {
        Cache<String, String> cache = vaultCache();
        return cache == null ? null : cache.get(cacheKey);
    }

    private void cachePut(String cacheKey, String value) {
        Cache<String, String> cache = vaultCache();
        if (cache != null) {
            cache.put(cacheKey, value, config.getCacheTtlMs(), TimeUnit.MILLISECONDS);
        }
    }

    private Cache<String, String> vaultCache() {
        return HashicorpVaultCaches.get(session, config);
    }

    private static VaultRawSecret wrap(String value) {
        return DefaultVaultRawSecret.forBuffer(Optional.of(ByteBuffer.wrap(value.getBytes(StandardCharsets.UTF_8))));
    }
}
