package io.github.sakc.keycloak.vault.hashicorp;

import io.github.sakc.keycloak.vault.hashicorp.cache.HashicorpVaultCacheKey;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertNotEquals;

class HashicorpVaultCacheKeyTest {

    @Test
    void separatesRealmsMountsFieldsAndVersions() {
        HashicorpVaultConfig latest = HashicorpVaultConfig.from(new MapScope(Map.of()));
        HashicorpVaultConfig versionThree = HashicorpVaultConfig.from(new MapScope(Map.of("kv-read-version", "3")));

        String realmA = HashicorpVaultCacheKey.forSecret("realm-a", "shared/path", latest).asString();
        String realmB = HashicorpVaultCacheKey.forSecret("realm-b", "shared/path", latest).asString();
        String versioned = HashicorpVaultCacheKey.forSecret("realm-a", "shared/path", versionThree).asString();

        assertNotEquals(realmA, realmB);
        assertNotEquals(realmA, versioned);
    }
}