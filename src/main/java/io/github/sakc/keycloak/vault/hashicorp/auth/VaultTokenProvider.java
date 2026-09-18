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

import org.keycloak.models.KeycloakSession;

/**
 * Supplies a Vault client token. Implementations are created once in the vault factory.
 */
public interface VaultTokenProvider {

    /**
     * @return a usable Vault token, or {@code null} if authentication failed
     */
    String getToken(KeycloakSession session);

    /**
     * Marks the cached token invalid so the next {@link #getToken(KeycloakSession)} re-authenticates.
     */
    void invalidate();

    void close();
}
