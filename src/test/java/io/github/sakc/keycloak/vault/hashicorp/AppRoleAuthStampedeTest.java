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

import io.github.sakc.keycloak.vault.hashicorp.auth.AppRoleTokenProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;

import java.io.IOException;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Concurrent callers hitting an expired/uncached token must trigger exactly one Vault login,
 * not one login per thread ("authentication stampede").
 */
class AppRoleAuthStampedeTest {

    private static final String LOGIN_BODY = "{\"auth\":{\"client_token\":\"s.stampede\",\"lease_duration\":3600}}";

    private FakeVaultServer server;
    private KeycloakSession session;

    @BeforeEach
    void setUp() throws IOException {
        server = FakeVaultServer.start();
        session = FakeKeycloakSessions.create();
    }

    @AfterEach
    void tearDown() {
        server.close();
    }

    @Test
    void concurrentGetTokenCallsTriggerASingleLogin() throws InterruptedException {
        server.alwaysRespond(200, LOGIN_BODY);
        Config.Scope scope = new MapScope(Map.of("url", server.baseUrl()));
        HashicorpVaultClient client = new HashicorpVaultClient(HashicorpVaultConfig.from(scope));
        AppRoleTokenProvider tokenProvider = new AppRoleTokenProvider(client, "approle", "role-id", "secret-id");

        int threadCount = 16;
        ExecutorService pool = Executors.newFixedThreadPool(threadCount);
        CountDownLatch ready = new CountDownLatch(threadCount);
        CountDownLatch start = new CountDownLatch(1);
        Set<String> tokensSeen = java.util.concurrent.ConcurrentHashMap.newKeySet();
        AtomicReference<Throwable> failure = new AtomicReference<>();
        try {
            for (int i = 0; i < threadCount; i++) {
                pool.submit(() -> {
                    ready.countDown();
                    try {
                        start.await();
                        tokensSeen.add(tokenProvider.getToken(session));
                    } catch (Throwable t) {
                        failure.set(t);
                    }
                });
            }
            assertTrue(ready.await(5, TimeUnit.SECONDS));
            start.countDown();
        } finally {
            pool.shutdown();
            assertTrue(pool.awaitTermination(5, TimeUnit.SECONDS));
        }

        assertEquals(null, failure.get());
        assertEquals(Set.of("s.stampede"), tokensSeen);
        assertEquals(1, server.requestCount(), "concurrent callers must share a single Vault login");
    }
}
