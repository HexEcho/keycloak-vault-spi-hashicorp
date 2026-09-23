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

import java.util.Objects;

/** A collision-resistant, deterministic identity for one Vault field lookup. */
public record HashicorpVaultCacheKey(String realm, String mount, String path, String field,
                                     int kvVersion, Integer version) {

    public HashicorpVaultCacheKey {
        realm = require(realm, "realm");
        mount = require(mount, "mount");
        path = require(path, "path");
        field = require(field, "field");
        if (kvVersion != 1 && kvVersion != 2) {
            throw new IllegalArgumentException("kvVersion must be 1 or 2");
        }
        if (version != null && (kvVersion != 2 || version < 1)) {
            throw new IllegalArgumentException("version is valid only for KV v2 and must be positive");
        }
    }

    public static HashicorpVaultCacheKey forSecret(String realm, String vaultKey, HashicorpVaultConfig config) {
        return new HashicorpVaultCacheKey(realm, config.getKvMount(), vaultKey, config.getKvField(),
                config.getKvVersion(), config.getKvReadVersion());
    }

    public String asString() {
        return encode(realm) + '|' + encode(mount) + '|' + encode(path) + '|' + encode(field) + '|'
                + kvVersion + '|' + (version == null ? "latest" : version);
    }

    private static String require(String value, String name) {
        return Objects.requireNonNull(value, name);
    }

    private static String encode(String value) {
        return value.length() + ":" + value;
    }
}