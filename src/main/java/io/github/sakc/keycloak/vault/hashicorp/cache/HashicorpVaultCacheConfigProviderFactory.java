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

import org.infinispan.configuration.cache.CacheMode;
import org.infinispan.configuration.cache.ConfigurationBuilder;
import org.infinispan.configuration.parsing.ConfigurationBuilderHolder;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.spi.infinispan.impl.embedded.DefaultCacheEmbeddedConfigProviderFactory;

import java.io.IOException;

/**
 * Registers a LOCAL Infinispan cache for HashiCorp vault secrets on Keycloak's cache manager.
 * Same factory id as Keycloak's default ({@code default}) with a higher order so this instance is selected.
 */
public class HashicorpVaultCacheConfigProviderFactory extends DefaultCacheEmbeddedConfigProviderFactory {

    public static final String CACHE_NAME = HashicorpVaultCaches.CACHE_NAME;

    @Override
    protected ConfigurationBuilderHolder createConfiguration(KeycloakSessionFactory factory) throws IOException {
        ConfigurationBuilderHolder holder = super.createConfiguration(factory);
        ConfigurationBuilder builder = holder.newConfigurationBuilder(CACHE_NAME);
        builder.clustering().cacheMode(CacheMode.LOCAL);
        builder.memory().maxCount(10_000);
        return holder;
    }

    @Override
    public int order() {
        return super.order() + 10;
    }
}
