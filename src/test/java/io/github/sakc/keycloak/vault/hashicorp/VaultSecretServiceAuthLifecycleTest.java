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

import io.github.sakc.keycloak.vault.hashicorp.auth.VaultTokenProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * Verifies the deterministic authentication lifecycle owned by {@link VaultSecretService}:
 * a single authorization failure invalidates the token and retries exactly once, and a second
 * consecutive failure is returned to the caller instead of looping.
 */
class VaultSecretServiceAuthLifecycleTest {

    private static final String KV2_BODY = "{\"data\":{\"data\":{\"value\":\"secret-value\"}}}";

    private FakeVaultServer server;
    private KeycloakSession session;
    private HashicorpVaultClient client;

    @BeforeEach
    void setUp() throws IOException {
        server = FakeVaultServer.start();
        session = FakeKeycloakSessions.create();
        Config.Scope scope = new MapScope(Map.of(
                "url", server.baseUrl(),
                "retry-max-attempts", "1"));
        client = new HashicorpVaultClient(HashicorpVaultConfig.from(scope));
    }

    @AfterEach
    void tearDown() {
        server.close();
    }

    @Test
    void authorizationFailureInvalidatesTokenAndRetriesExactlyOnce() {
        server.enqueue(403, "{}");
        server.enqueue(200, KV2_BODY);
        CountingTokenProvider tokenProvider = new CountingTokenProvider("token-A", "token-B");
        VaultSecretService service = new VaultSecretService(client, tokenProvider);

        HashicorpVaultClient.SecretLookup lookup = service.readSecret(session, "demo/app");

        assertEquals("secret-value", lookup.value());
        assertEquals(1, tokenProvider.invalidateCount.get());
        assertEquals(2, server.requestCount());
    }

    @Test
    void secondConsecutiveAuthorizationFailureDoesNotLoopIndefinitely() {
        server.alwaysRespond(403, "{}");
        CountingTokenProvider tokenProvider = new CountingTokenProvider("token-A", "token-B");
        VaultSecretService service = new VaultSecretService(client, tokenProvider);

        HashicorpVaultClient.SecretLookup lookup = service.readSecret(session, "demo/app");

        assertNull(lookup.value());
        assertEquals(403, lookup.status());
        assertEquals(1, tokenProvider.invalidateCount.get(), "must retry auth exactly once, never loop");
        assertEquals(2, server.requestCount());
    }

    /** Fake provider returning a first token, then a second one after the first invalidate(). */
    private static final class CountingTokenProvider implements VaultTokenProvider {
        private final String firstToken;
        private final String secondToken;
        private final AtomicInteger invalidateCount = new AtomicInteger();
        private volatile boolean invalidated;

        CountingTokenProvider(String firstToken, String secondToken) {
            this.firstToken = firstToken;
            this.secondToken = secondToken;
        }

        @Override
        public String getToken(KeycloakSession session) {
            return invalidated ? secondToken : firstToken;
        }

        @Override
        public void invalidate() {
            invalidated = true;
            invalidateCount.incrementAndGet();
        }

        @Override
        public void close() {
        }
    }
}
