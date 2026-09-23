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

import io.github.sakc.keycloak.vault.hashicorp.auth.KubernetesTokenProvider;
import io.github.sakc.keycloak.vault.hashicorp.auth.StaticTokenProvider;
import io.github.sakc.keycloak.vault.hashicorp.auth.VaultTokenProvider;
import io.github.sakc.keycloak.vault.hashicorp.exception.VaultConfigurationException;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class HashicorpVaultProviderFactoryTest {

    @Test
    void kubernetesAuthMethodWithoutRoleFailsFastAtInit() {
        HashicorpVaultProviderFactory factory = new HashicorpVaultProviderFactory();
        assertThrows(VaultConfigurationException.class, () -> factory.init(new MapScope(Map.of(
                "url", "http://vault:8200",
                "auth-method", "kubernetes"
        ))));
    }

    @Test
    void approleAuthMethodWithoutCredentialsFailsFastAtInit() {
        HashicorpVaultProviderFactory factory = new HashicorpVaultProviderFactory();
        assertThrows(VaultConfigurationException.class, () -> factory.init(new MapScope(Map.of(
                "url", "http://vault:8200",
                "auth-method", "approle"
        ))));
    }

    @Test
    void kubernetesAuthMethodDoesNotRequireAStaticToken() {
        try (LogCapture capture = LogCapture.forClass(HashicorpVaultProviderFactory.class)) {
            HashicorpVaultProviderFactory factory = new HashicorpVaultProviderFactory();
            factory.init(new MapScope(Map.of(
                    "url", "http://vault:8200",
                    "auth-method", "kubernetes",
                    "kubernetes-role", "keycloak",
                    "kubernetes-jwt-path", "/var/run/secrets/kubernetes.io/serviceaccount/token"
            )));
            try {
                VaultTokenProvider tokenProvider = factory.tokenProvider();
                assertInstanceOf(KubernetesTokenProvider.class, tokenProvider);
                assertFalse(capture.anyMessageContains("Vault token is not configured"),
                        "Kubernetes auth must not require a static Vault token");
            } finally {
                factory.close();
            }
        }
    }

    @Test
    void tokenAuthMethodStillRequiresStaticTokenWarningWhenMissing() {
        try (LogCapture capture = LogCapture.forClass(HashicorpVaultProviderFactory.class)) {
            HashicorpVaultProviderFactory factory = new HashicorpVaultProviderFactory();
            factory.init(new MapScope(Map.of(
                    "url", "http://vault:8200",
                    "auth-method", "token"
            )));
            try {
                assertInstanceOf(StaticTokenProvider.class, factory.tokenProvider());
                assertTrue(capture.anyMessageContains("Vault token is not configured"),
                        "Existing token auth-method behaviour must be preserved");
            } finally {
                factory.close();
            }
        }
    }

    @Test
    void resolveKeyUsesForwardSlashByDefault() {
        HashicorpVaultProviderFactory factory = new HashicorpVaultProviderFactory();
        factory.init(new MapScope(Map.of("url", "http://vault:8200")));
        try {
            org.junit.jupiter.api.Assertions.assertEquals("demo/my-client", factory.resolveKey("demo", "my-client"));
        } finally {
            factory.close();
        }
    }

    @Test
    void resolveManagedKeyReturnsNullWhenNotConfiguredPreservingBackwardCompatiblePath() {
        HashicorpVaultProviderFactory factory = new HashicorpVaultProviderFactory();
        factory.init(new MapScope(Map.of("url", "http://vault:8200")));
        try {
            org.junit.jupiter.api.Assertions.assertNull(factory.resolveManagedKey("demo", "my-client"));
        } finally {
            factory.close();
        }
    }

    @Test
    void resolveManagedKeyIsRealmIsolatedWhenConfigured() {
        HashicorpVaultProviderFactory factory = new HashicorpVaultProviderFactory();
        factory.init(new MapScope(Map.of(
                "url", "http://vault:8200",
                "managed-secret-prefix", "managed"
        )));
        try {
            String demo = factory.resolveManagedKey("demo", "my-client");
            String other = factory.resolveManagedKey("other-realm", "my-client");
            org.junit.jupiter.api.Assertions.assertEquals("demo/managed/my-client", demo);
            org.junit.jupiter.api.Assertions.assertNotEquals(demo, other);
        } finally {
            factory.close();
        }
    }
}
