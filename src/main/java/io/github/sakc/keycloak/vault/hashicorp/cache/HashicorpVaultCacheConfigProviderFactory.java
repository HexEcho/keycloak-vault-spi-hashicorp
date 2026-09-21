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

import org.infinispan.configuration.parsing.ConfigurationBuilderHolder;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.spi.infinispan.impl.embedded.DefaultCacheEmbeddedConfigProviderFactory;

import java.io.IOException;

/**
 * Keeps Keycloak's normal cache configuration. The vault cache is created lazily because its bound
 * is a provider setting rather than a server-wide Infinispan setting.
 */
public class HashicorpVaultCacheConfigProviderFactory extends DefaultCacheEmbeddedConfigProviderFactory {

    public static final String CACHE_NAME = HashicorpVaultCaches.CACHE_NAME;

    @Override
    protected ConfigurationBuilderHolder createConfiguration(KeycloakSessionFactory factory) throws IOException {
        ConfigurationBuilderHolder holder = super.createConfiguration(factory);
        return holder;
    }

    @Override
    public int order() {
        return super.order() + 10;
    }
}
