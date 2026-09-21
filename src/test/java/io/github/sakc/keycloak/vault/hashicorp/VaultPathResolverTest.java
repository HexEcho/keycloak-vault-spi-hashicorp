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
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class VaultPathResolverTest {

    @Test
    void safeSegmentsAcceptOrdinaryRealmAndKeyNames() {
        assertTrue(VaultPathResolver.isSafeSegment("demo"));
        assertTrue(VaultPathResolver.isSafeSegment("my-client_01"));
    }

    @Test
    void rejectsPathTraversalSegments() {
        assertFalse(VaultPathResolver.isSafeSegment(".."));
        assertFalse(VaultPathResolver.isSafeSegment("../secret"));
        assertFalse(VaultPathResolver.isSafeSegment("realm/../other"));
        assertFalse(VaultPathResolver.isSafeResolvedKey("../secret"));
        assertFalse(VaultPathResolver.isSafeResolvedKey("master/../ldapBc"));
        assertFalse(VaultPathResolver.isSafeResolvedKey("master/..%2fldapBc/.."));
    }

    @Test
    void rejectsEmptyOrBlankSegments() {
        assertFalse(VaultPathResolver.isSafeSegment(""));
        assertFalse(VaultPathResolver.isSafeSegment(null));
        assertFalse(VaultPathResolver.isSafeSegment("   "));
        assertFalse(VaultPathResolver.isSafeResolvedKey(""));
        assertFalse(VaultPathResolver.isSafeResolvedKey(null));
    }

    @Test
    void rejectsLeadingTrailingSeparatorsAndDoubleSeparators() {
        assertFalse(VaultPathResolver.isSafeSegment("/leading"));
        assertFalse(VaultPathResolver.isSafeSegment("trailing/"));
        assertFalse(VaultPathResolver.isSafeResolvedKey("realm//key"));
        assertFalse(VaultPathResolver.isSafeResolvedKey("/realm/key"));
        assertFalse(VaultPathResolver.isSafeResolvedKey("realm/key/"));
    }

    @Test
    void rejectsControlCharactersIncludingNul() {
        assertFalse(VaultPathResolver.isSafeSegment("ldap\0Bc"));
        assertFalse(VaultPathResolver.isSafeResolvedKey("realm/ldap\0Bc"));
    }

    @Test
    void requireSafeRealmThrowsOnEmptyOrMalformedRealm() {
        assertThrows(IllegalArgumentException.class, () -> VaultPathResolver.requireSafeRealm(""));
        assertThrows(IllegalArgumentException.class, () -> VaultPathResolver.requireSafeRealm(null));
        assertThrows(IllegalArgumentException.class, () -> VaultPathResolver.requireSafeRealm("../master"));
        assertEquals("demo", VaultPathResolver.requireSafeRealm("demo"));
    }

    @Test
    void requireSafeKeyThrowsOnMalformedKey() {
        assertThrows(IllegalArgumentException.class, () -> VaultPathResolver.requireSafeKey(""));
        assertThrows(IllegalArgumentException.class, () -> VaultPathResolver.requireSafeKey("../secret"));
        assertEquals("clientId", VaultPathResolver.requireSafeKey("clientId"));
    }

    @Test
    void managedKeyIsDeterministicAndRealmIsolated() {
        String demoKey = VaultPathResolver.managedKey("demo", "managed", "my-client");
        String otherRealmKey = VaultPathResolver.managedKey("other-realm", "managed", "my-client");
        assertEquals("demo/managed/my-client", demoKey);
        assertNotEquals(demoKey, otherRealmKey, "realm A must never resolve to realm B's managed secret path");
        assertTrue(VaultPathResolver.isSafeResolvedKey(demoKey));
    }

    @Test
    void managedKeyRejectsTraversalInAnyComponent() {
        assertThrows(IllegalArgumentException.class, () -> VaultPathResolver.managedKey("../demo", "managed", "client"));
        assertThrows(IllegalArgumentException.class, () -> VaultPathResolver.managedKey("demo", "../managed", "client"));
        assertThrows(IllegalArgumentException.class, () -> VaultPathResolver.managedKey("demo", "managed", "../client"));
        assertThrows(IllegalArgumentException.class, () -> VaultPathResolver.managedKey("", "managed", "client"));
        assertThrows(IllegalArgumentException.class, () -> VaultPathResolver.managedKey("demo", "managed", ""));
    }

    @Test
    void secretUrlBuildsKvV2AndKvV1Paths() {
        HashicorpVaultConfig v2 = configWithKvVersion(2);
        HashicorpVaultConfig v1 = configWithKvVersion(1);
        assertEquals("http://vault:8200/v1/secret/data/demo/my-client", VaultPathResolver.secretUrl(v2, "demo/my-client"));
        assertEquals("http://vault:8200/v1/secret/demo/my-client", VaultPathResolver.secretUrl(v1, "demo/my-client"));
    }

    @Test
    void secretUrlRejectsUnsafeKeyInsteadOfSanitizingIt() {
        HashicorpVaultConfig config = configWithKvVersion(2);
        assertThrows(IllegalArgumentException.class, () -> VaultPathResolver.secretUrl(config, "../secret"));
        assertThrows(IllegalArgumentException.class, () -> VaultPathResolver.deleteUrl(config, "demo/../other"));
    }

    private static HashicorpVaultConfig configWithKvVersion(int version) {
        return HashicorpVaultConfig.from(new MapScope(java.util.Map.of(
                "url", "http://vault:8200",
                "kv-mount", "secret",
                "kv-version", String.valueOf(version)
        )));
    }
}
