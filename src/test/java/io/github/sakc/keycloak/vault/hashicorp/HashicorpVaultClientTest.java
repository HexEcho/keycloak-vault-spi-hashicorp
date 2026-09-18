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

import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.Test;
import org.keycloak.util.JsonSerialization;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class HashicorpVaultClientTest {

    @Test
    void kvV2PathUsesDataSegment() {
        HashicorpVaultConfig config = config("http://127.0.0.1:8200", "secret", 2);
        assertEquals("http://127.0.0.1:8200/v1/secret/data/master_ldapBc",
                HashicorpVaultClient.secretUrl(config, "master_ldapBc"));
    }

    @Test
    void kvV1PathOmitsDataSegment() {
        HashicorpVaultConfig config = config("http://vault:8200/", "secret", 1);
        assertEquals("http://vault:8200/v1/secret/master_ldapBc",
                HashicorpVaultClient.secretUrl(config, "master_ldapBc"));
    }

    @Test
    void extractKvV2Field() throws IOException {
        JsonNode root = JsonSerialization.mapper.readTree("""
                {"data":{"data":{"value":"bind-password","username":"cn=admin"}}}
                """);
        assertEquals("bind-password", HashicorpVaultClient.extractField(root, 2, "value"));
        assertEquals("cn=admin", HashicorpVaultClient.extractField(root, 2, "username"));
        assertNull(HashicorpVaultClient.extractField(root, 2, "missing"));
    }

    @Test
    void extractKvV1Field() throws IOException {
        JsonNode root = JsonSerialization.mapper.readTree("""
                {"data":{"value":"smtp-password"}}
                """);
        assertEquals("smtp-password", HashicorpVaultClient.extractField(root, 1, "value"));
    }

    @Test
    void kvV2WriteBodyWrapsField() {
        HashicorpVaultConfig config = config("http://127.0.0.1:8200", "secret", 2);
        assertEquals(java.util.Map.of("data", java.util.Map.of("value", "secret")),
                HashicorpVaultClient.writeBody(config, "secret"));
    }

    @Test
    void kvV1WriteBodyIsFlat() {
        HashicorpVaultConfig config = config("http://vault:8200/", "secret", 1);
        assertEquals(java.util.Map.of("value", "secret"), HashicorpVaultClient.writeBody(config, "secret"));
    }

    private static HashicorpVaultConfig config(String url, String mount, int version) {
        org.keycloak.Config.Scope scope = new MapScope(java.util.Map.of(
                "url", url,
                "kv-mount", mount,
                "kv-version", String.valueOf(version)
        ));
        return HashicorpVaultConfig.from(scope);
    }
}
