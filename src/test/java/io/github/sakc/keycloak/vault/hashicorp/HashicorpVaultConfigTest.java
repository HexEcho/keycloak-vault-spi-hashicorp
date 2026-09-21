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

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class HashicorpVaultConfigTest {

    @Test
    void readsDefaultsAndNormalizesUrlAndMount() {
        HashicorpVaultConfig config = HashicorpVaultConfig.from(new MapScope(java.util.Map.of(
                "url", "http://127.0.0.1:8200/",
                "kv-mount", "/secret/"
        )));
        assertEquals("http://127.0.0.1:8200", config.getUrl());
        assertEquals("secret", config.getKvMount());
        assertEquals(2, config.getKvVersion());
        assertEquals("value", config.getKvField());
        assertEquals(300_000L, config.getCacheTtlMs());
        assertTrue(config.cacheEnabled());
        assertEquals("token", config.getAuthMethod());
        assertNull(config.getNamespace());
    }

    @Test
    void disablesCacheWhenTtlNonPositive() {
        HashicorpVaultConfig config = HashicorpVaultConfig.from(new MapScope(java.util.Map.of(
                "cache-ttl", "0"
        )));
        assertFalse(config.cacheEnabled());
    }

    @Test
    void trimsNamespaceAndKeepsNestedPath() {
        HashicorpVaultConfig config = HashicorpVaultConfig.from(new MapScope(java.util.Map.of(
                "namespace", "  admin/team-a  "
        )));
        assertEquals("admin/team-a", config.getNamespace());
    }

    @Test
    void treatsBlankNamespaceAsUnset() {
        HashicorpVaultConfig config = HashicorpVaultConfig.from(new MapScope(java.util.Map.of(
                "namespace", "   "
        )));
        assertNull(config.getNamespace());
    }

    @Test
    void normalizesCertificateAuthAliases() {
        assertEquals("cert", HashicorpVaultConfig.normalizeAuthMethod("certificate"));
        assertEquals("cert", HashicorpVaultConfig.normalizeAuthMethod("tls"));
        assertEquals("cert", HashicorpVaultConfig.normalizeAuthMethod("tls-cert"));
        assertEquals("approle", HashicorpVaultConfig.normalizeAuthMethod("AppRole"));
        assertEquals("token", HashicorpVaultConfig.normalizeAuthMethod("unknown"));
    }

    @Test
    void recognizesKubernetesAuthMethod() {
        assertEquals("kubernetes", HashicorpVaultConfig.normalizeAuthMethod("kubernetes"));
        assertEquals("kubernetes", HashicorpVaultConfig.normalizeAuthMethod("Kubernetes"));
    }

    @Test
    void managedSecretPrefixIsUnsetByDefaultForBackwardCompatibility() {
        HashicorpVaultConfig config = HashicorpVaultConfig.from(new MapScope(java.util.Map.of(
                "url", "http://127.0.0.1:8200"
        )));
        assertNull(config.getManagedSecretPrefix());
    }

    @Test
    void managedSecretPrefixIsTrimmedAndBlankTreatedAsUnset() {
        HashicorpVaultConfig configured = HashicorpVaultConfig.from(new MapScope(java.util.Map.of(
                "managed-secret-prefix", "  managed  "
        )));
        assertEquals("managed", configured.getManagedSecretPrefix());

        HashicorpVaultConfig blank = HashicorpVaultConfig.from(new MapScope(java.util.Map.of(
                "managed-secret-prefix", "   "
        )));
        assertNull(blank.getManagedSecretPrefix());
    }
}
