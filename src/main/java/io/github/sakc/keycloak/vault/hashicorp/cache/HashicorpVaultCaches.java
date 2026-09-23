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
package io.github.sakc.keycloak.vault.hashicorp.cache;

import io.github.sakc.keycloak.vault.hashicorp.HashicorpVaultConfig;
import org.infinispan.Cache;
import org.infinispan.configuration.cache.CacheMode;
import org.infinispan.configuration.cache.ConfigurationBuilder;
import org.infinispan.manager.EmbeddedCacheManager;
import org.jboss.logging.Logger;
import org.keycloak.connections.infinispan.InfinispanConnectionProvider;
import org.keycloak.models.KeycloakSession;

/**
 * Uses Keycloak's EmbeddedCacheManager (never a private CacheManager).
 * Defines a LOCAL cache on first use when it was not present in the boot configuration.
 */
public final class HashicorpVaultCaches {

    public static final String CACHE_NAME = "hashicorp-vault";

    private static final Logger log = Logger.getLogger(HashicorpVaultCaches.class);
    private static final Object DEFINE_LOCK = new Object();
    private static volatile boolean unavailableLogged;

    private HashicorpVaultCaches() {
    }

    public static Cache<String, String> get(KeycloakSession session, HashicorpVaultConfig config) {
        InfinispanConnectionProvider infinispan = session.getProvider(InfinispanConnectionProvider.class);
        if (infinispan == null) {
            return null;
        }
        try {
            defineLocalCache(infinispan, config.getCacheMaxEntries());
            return infinispan.getCache(CACHE_NAME, true);
        } catch (RuntimeException e) {
            if (!unavailableLogged) {
                unavailableLogged = true;
                log.warn("Infinispan cache 'hashicorp-vault' is unavailable; vault lookups will not be cached.", e);
            }
            return null;
        }
    }

    private static void defineLocalCache(InfinispanConnectionProvider infinispan, int maxEntries) {
        synchronized (DEFINE_LOCK) {
            Cache<?, ?> keys = infinispan.getCache(InfinispanConnectionProvider.KEYS_CACHE_NAME, false);
            if (keys == null) {
                return;
            }
            EmbeddedCacheManager manager = keys.getCacheManager();
            if (manager.getCacheConfiguration(CACHE_NAME) != null) {
                return;
            }
            ConfigurationBuilder builder = new ConfigurationBuilder();
            builder.clustering().cacheMode(CacheMode.LOCAL);
                builder.memory().maxCount(maxEntries);
            manager.defineConfiguration(CACHE_NAME, builder.build());
                log.debugf("Defined LOCAL Infinispan cache hashicorp-vault on Keycloak's cache manager. maxEntries=%d",
                    maxEntries);
        }
    }
}
