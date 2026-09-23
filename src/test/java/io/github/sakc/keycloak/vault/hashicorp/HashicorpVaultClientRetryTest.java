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

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * End-to-end coverage of {@link HashicorpVaultClient} retry, timeout, and status-mapping
 * behavior against an in-process fake Vault server (see {@link FakeVaultServer}).
 */
class HashicorpVaultClientRetryTest {

    private static final String KV2_BODY = "{\"data\":{\"data\":{\"value\":\"secret-value\"}}}";

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
    void retriesTransientServerErrorThenSucceeds() {
        server.enqueue(503, "{}");
        server.enqueue(200, KV2_BODY);
        HashicorpVaultClient client = client(fastRetryOverrides(3));

        HashicorpVaultClient.SecretLookup lookup = client.readSecret(session, "token", "demo/app");

        assertEquals("secret-value", lookup.value());
        assertEquals(2, server.requestCount());
    }

    @Test
    void retriesRateLimitedThenSucceeds() {
        server.enqueue(429, "{}");
        server.enqueue(200, KV2_BODY);
        HashicorpVaultClient client = client(fastRetryOverrides(3));

        HashicorpVaultClient.SecretLookup lookup = client.readSecret(session, "token", "demo/app");

        assertEquals("secret-value", lookup.value());
        assertEquals(2, server.requestCount());
    }

    @ParameterizedTest
    @ValueSource(ints = {500, 502, 503, 504})
    void exhaustsRetriesOnPersistentServerErrorsAndReturnsLastStatus(int status) {
        server.alwaysRespond(status, "{}");
        HashicorpVaultClient client = client(fastRetryOverrides(3));

        HashicorpVaultClient.SecretLookup lookup = client.readSecret(session, "token", "demo/app");

        assertEquals(status, lookup.status());
        assertNull(lookup.value());
        assertEquals(3, server.requestCount());
    }

    @Test
    void doesNotRetryNotFound() {
        server.alwaysRespond(404, "{}");
        HashicorpVaultClient client = client(fastRetryOverrides(4));

        HashicorpVaultClient.SecretLookup lookup = client.readSecret(session, "token", "demo/app");

        assertEquals(404, lookup.status());
        assertNull(lookup.value());
        assertEquals(1, server.requestCount());
    }

    @Test
    void doesNotRetryForbidden() {
        server.alwaysRespond(403, "{}");
        HashicorpVaultClient client = client(fastRetryOverrides(4));

        HashicorpVaultClient.SecretLookup lookup = client.readSecret(session, "token", "demo/app");

        assertTrue(lookup.isForbidden());
        assertEquals(1, server.requestCount());
    }

    @Test
    void doesNotRetryMalformedRequest() {
        server.alwaysRespond(400, "{}");
        HashicorpVaultClient client = client(fastRetryOverrides(4));

        HashicorpVaultClient.SecretLookup lookup = client.readSecret(session, "token", "demo/app");

        assertEquals(400, lookup.status());
        assertEquals(1, server.requestCount());
    }

    @Test
    void malformedJsonBodyIsHandledGracefullyWithoutThrowing() {
        server.alwaysRespond(200, "{not-json");
        HashicorpVaultClient client = client(fastRetryOverrides(2));

        HashicorpVaultClient.SecretLookup lookup = client.readSecret(session, "token", "demo/app");

        assertNull(lookup.value());
        assertEquals(1, server.requestCount());
    }

    @Test
    void connectionFailureRetriesThenFailsBounded() throws IOException {
        int deadPort = findAndCloseEphemeralPort();
        HashicorpVaultClient client = clientForUrl("http://127.0.0.1:" + deadPort, fastRetryOverrides(2));

        HashicorpVaultClient.SecretLookup lookup = client.readSecret(session, "token", "demo/app");

        assertEquals(0, lookup.status());
        assertNull(lookup.value());
    }

    @Test
    void readTimeoutRetriesThenFailsBounded() {
        server.delayEveryResponseBy(400);
        server.alwaysRespond(200, KV2_BODY);
        Map<String, String> overrides = fastRetryOverrides(2);
        overrides.put("read-timeout-ms", "50");
        HashicorpVaultClient client = client(overrides);

        HashicorpVaultClient.SecretLookup lookup = client.readSecret(session, "token", "demo/app");

        assertEquals(0, lookup.status());
        assertNull(lookup.value());
        assertEquals(2, server.requestCount());
    }

    @Test
    void writeSecretRetriesTransientErrorThenSucceeds() {
        server.enqueue(502, "{}");
        server.enqueue(200, "{}");
        HashicorpVaultClient client = client(fastRetryOverrides(3));

        HashicorpVaultClient.WriteResult result = client.writeSecret(session, "token", "demo/app", "s3cr3t");

        assertTrue(result.success());
        assertEquals(2, server.requestCount());
    }

    @Test
    void deleteSecretTreats404AsSuccessWithoutRetry() {
        server.alwaysRespond(404, "{}");
        HashicorpVaultClient client = client(fastRetryOverrides(3));

        HashicorpVaultClient.DeleteResult result = client.deleteSecret(session, "token", "demo/app");

        assertTrue(result.success());
        assertEquals(1, server.requestCount());
    }

    @Test
    void healthCheckReportsHealthyOnOk() {
        server.alwaysRespond(200, "{\"initialized\":true}");
        HashicorpVaultClient client = client(fastRetryOverrides(3));

        HashicorpVaultClient.HealthStatus status = client.healthCheck(session);

        assertTrue(status.healthy());
        assertEquals(200, status.httpStatus());
    }

    @Test
    void healthCheckReportsUnhealthyOnServerError() {
        server.alwaysRespond(503, "{}");
        HashicorpVaultClient client = client(fastRetryOverrides(3));

        HashicorpVaultClient.HealthStatus status = client.healthCheck(session);

        assertTrue(!status.healthy());
        assertEquals(503, status.httpStatus());
        assertEquals(1, server.requestCount(), "health check must never retry");
    }

    @Test
    void healthCheckReportsErrorOnConnectionFailure() throws IOException {
        int deadPort = findAndCloseEphemeralPort();
        HashicorpVaultClient client = clientForUrl("http://127.0.0.1:" + deadPort, fastRetryOverrides(3));

        HashicorpVaultClient.HealthStatus status = client.healthCheck(session);

        assertTrue(!status.healthy());
        assertTrue(status.error() != null);
    }

    private static Map<String, String> fastRetryOverrides(int maxAttempts) {
        Map<String, String> overrides = new HashMap<>();
        overrides.put("retry-max-attempts", String.valueOf(maxAttempts));
        overrides.put("retry-initial-delay-ms", "5");
        overrides.put("retry-max-delay-ms", "20");
        overrides.put("connect-timeout-ms", "500");
        overrides.put("read-timeout-ms", "2000");
        overrides.put("request-timeout-ms", "500");
        return overrides;
    }

    private HashicorpVaultClient client(Map<String, String> overrides) {
        return clientForUrl(server.baseUrl(), overrides);
    }

    private static HashicorpVaultClient clientForUrl(String url, Map<String, String> overrides) {
        Map<String, String> values = new HashMap<>(overrides);
        values.put("url", url);
        Config.Scope scope = new MapScope(values);
        return new HashicorpVaultClient(HashicorpVaultConfig.from(scope));
    }

    private static int findAndCloseEphemeralPort() throws IOException {
        try (java.net.ServerSocket socket = new java.net.ServerSocket(0)) {
            return socket.getLocalPort();
        }
    }
}
