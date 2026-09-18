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
package io.github.sakc.keycloak.vault.hashicorp.auth;

import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;

/**
 * Uses a pre-configured static Vault token.
 */
public final class StaticTokenProvider implements VaultTokenProvider {

    private static final Logger log = Logger.getLogger(StaticTokenProvider.class);

    private volatile String token;

    public StaticTokenProvider(String token) {
        this.token = token;
    }

    @Override
    public String getToken(KeycloakSession session) {
        return token;
    }

    @Override
    public void invalidate() {
        log.warn("Static Vault token cannot be renewed. HTTP 403 will persist until a valid token is configured.");
    }

    @Override
    public void close() {
        token = null;
    }
}
