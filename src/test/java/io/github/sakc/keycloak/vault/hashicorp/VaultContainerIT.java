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
import io.github.sakc.keycloak.vault.hashicorp.auth.StaticTokenProvider;
import io.github.sakc.keycloak.vault.hashicorp.auth.VaultTokenProvider;
import com.github.dockerjava.api.DockerClient;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.keycloak.models.KeycloakSession;
import org.testcontainers.DockerClientFactory;
import org.testcontainers.containers.Container;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import java.io.IOException;
import java.time.Duration;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * End-to-end integration tests against a real HashiCorp Vault dev-mode server (Testcontainers).
 * These exercise the same {@link HashicorpVaultClient} / {@link VaultSecretService} code paths
 * Keycloak uses at runtime, but talk to an actual Vault HTTP API instead of a scripted fake.
 *
 * <p>Requires a working Docker daemon. Skipped automatically (via {@link org.junit.jupiter.api.Assumptions})
 * when Docker is not available, so {@code mvn test} never depends on it; only {@code mvn verify}
 * (failsafe, {@code *IT.java}) runs this class.</p>
 */
@Testcontainers
class VaultContainerIT {

    private static final String ROOT_TOKEN = "root-integration-test-token";
    private static final boolean DOCKER_AVAILABLE = isDockerAvailable();

    private static GenericContainer<?> vault;

    @BeforeAll
    static void startVaultAndConfigureEngines() throws IOException, InterruptedException {
        assumeTrue(DOCKER_AVAILABLE, "Docker is not available; skipping Vault Testcontainers integration tests");

        vault = new GenericContainer<>(DockerImageName.parse("hashicorp/vault:1.17"))
                .withExposedPorts(8200)
                .withEnv("VAULT_DEV_ROOT_TOKEN_ID", ROOT_TOKEN)
                .withEnv("VAULT_DEV_LISTEN_ADDRESS", "0.0.0.0:8200")
                .withEnv("VAULT_ADDR", "http://127.0.0.1:8200")
                .withEnv("VAULT_TOKEN", ROOT_TOKEN)
                .waitingFor(Wait.forHttp("/v1/sys/health").forStatusCode(200));
        vault.start();

        // KV v2 is enabled by default at "secret/" in dev mode; add a KV v1 mount for KV v1 tests.
        exec("vault", "secrets", "enable", "-path=kv1", "-version=1", "kv");

        // AppRole auth for the AppRole integration test.
        exec("vault", "auth", "enable", "approle");
        exec("vault", "policy", "write", "it-policy", "-");
        writePolicy();
        exec("vault", "write", "auth/approle/role/it-role", "token_policies=it-policy", "token_ttl=1h");
    }

    @AfterAll
    static void stopVault() {
        if (vault != null) {
            vault.stop();
        }
    }

    private static boolean isDockerAvailable() {
        try {
            return DockerClientFactory.instance().isDockerAvailable();
        } catch (Exception e) {
            return false;
        }
    }

    private static void writePolicy() throws IOException, InterruptedException {
        // vault policy write reads the HCL body from stdin when the file argument is "-"; the
        // simplest reliable way to feed stdin through execInContainer is a heredoc via sh -c.
        String hcl = "path \\\"secret/data/*\\\" { capabilities = [\\\"create\\\",\\\"update\\\",\\\"read\\\",\\\"delete\\\"] }\n"
                + "path \\\"secret/metadata/*\\\" { capabilities = [\\\"read\\\",\\\"delete\\\",\\\"list\\\"] }\n"
                + "path \\\"kv1/*\\\" { capabilities = [\\\"create\\\",\\\"update\\\",\\\"read\\\",\\\"delete\\\"] }\n";
        Container.ExecResult result = vault.execInContainer("sh", "-c",
                "printf '" + hcl + "' | vault policy write it-policy -");
        assertEquals(0, result.getExitCode(), result.getStderr());
    }

    private static Container.ExecResult exec(String... command) throws IOException, InterruptedException {
        Container.ExecResult result = vault.execInContainer(command);
        assertEquals(0, result.getExitCode(), "command " + String.join(" ", command) + " failed: " + result.getStderr());
        return result;
    }

    private HashicorpVaultConfig config(Map<String, String> overrides) {
        Map<String, String> values = new java.util.HashMap<>(Map.of(
                "url", "http://" + vault.getHost() + ":" + vault.getMappedPort(8200),
                "kv-mount", "secret",
                "kv-version", "2",
                "retry-max-attempts", "1"
        ));
        values.putAll(overrides);
        return HashicorpVaultConfig.from(new MapScope(values));
    }

    // --- KV v2: read, write, rotation, delete -------------------------------------------------

    @Test
    void kvV2WriteReadRotateAndDelete() {
        HashicorpVaultConfig cfg = config(Map.of());
        HashicorpVaultClient client = new HashicorpVaultClient(cfg);
        VaultSecretService service = new VaultSecretService(client, new StaticTokenProvider(ROOT_TOKEN));
        KeycloakSession session = FakeKeycloakSessions.create();

        HashicorpVaultClient.WriteResult write = service.writeSecret(session, "it/kv2-secret", "v1-value");
        assertTrue(write.success(), "write should succeed, status=" + write.status());

        HashicorpVaultClient.SecretLookup read = service.readSecret(session, "it/kv2-secret");
        assertEquals("v1-value", read.value());

        // Rotation: write a new version, confirm the read reflects the latest value.
        HashicorpVaultClient.WriteResult rotate = service.writeSecret(session, "it/kv2-secret", "v2-value");
        assertTrue(rotate.success());
        HashicorpVaultClient.SecretLookup afterRotation = service.readSecret(session, "it/kv2-secret");
        assertEquals("v2-value", afterRotation.value());

        HashicorpVaultClient.DeleteResult delete = service.deleteSecret(session, "it/kv2-secret");
        assertTrue(delete.success());

        HashicorpVaultClient.SecretLookup afterDelete = service.readSecret(session, "it/kv2-secret");
        assertNull(afterDelete.value());
    }

    @Test
    void kvV2VersionedReadReturnsThePinnedVersionNotLatest() {
        HashicorpVaultConfig cfg = config(Map.of());
        HashicorpVaultClient client = new HashicorpVaultClient(cfg);
        KeycloakSession session = FakeKeycloakSessions.create();

        client.writeSecret(session, ROOT_TOKEN, "it/versioned", "version-1");
        client.writeSecret(session, ROOT_TOKEN, "it/versioned", "version-2");

        HashicorpVaultClient.SecretLookup v1 = client.readSecret(session, ROOT_TOKEN, "it/versioned", 1);
        HashicorpVaultClient.SecretLookup latest = client.readSecret(session, ROOT_TOKEN, "it/versioned", null);

        assertEquals("version-1", v1.value());
        assertEquals("version-2", latest.value());
    }

    // --- KV v1 ------------------------------------------------------------------------------

    @Test
    void kvV1WriteAndRead() {
        HashicorpVaultConfig cfg = config(Map.of("kv-mount", "kv1", "kv-version", "1"));
        HashicorpVaultClient client = new HashicorpVaultClient(cfg);
        VaultSecretService service = new VaultSecretService(client, new StaticTokenProvider(ROOT_TOKEN));
        KeycloakSession session = FakeKeycloakSessions.create();

        HashicorpVaultClient.WriteResult write = service.writeSecret(session, "it/kv1-secret", "kv1-value");
        assertTrue(write.success(), "write should succeed, status=" + write.status());

        HashicorpVaultClient.SecretLookup read = service.readSecret(session, "it/kv1-secret");
        assertEquals("kv1-value", read.value());
    }

    // --- Token authentication ------------------------------------------------------------------

    @Test
    void tokenAuthenticationReadsASecret() {
        HashicorpVaultConfig cfg = config(Map.of());
        HashicorpVaultClient client = new HashicorpVaultClient(cfg);
        KeycloakSession session = FakeKeycloakSessions.create();
        client.writeSecret(session, ROOT_TOKEN, "it/token-auth", "token-value");

        VaultTokenProvider tokenProvider = new StaticTokenProvider(ROOT_TOKEN);
        VaultSecretService service = new VaultSecretService(client, tokenProvider);

        assertEquals("token-value", service.readSecret(session, "it/token-auth").value());
    }

    // --- AppRole authentication ------------------------------------------------------------------

    @Test
    void appRoleAuthenticationLogsInAndReadsASecret() throws IOException, InterruptedException {
        Container.ExecResult roleIdResult = exec("vault", "read", "-field=role_id", "auth/approle/role/it-role/role-id");
        Container.ExecResult secretIdResult = exec("vault", "write", "-field=secret_id", "-f", "auth/approle/role/it-role/secret-id");
        String roleId = roleIdResult.getStdout().trim();
        String secretId = secretIdResult.getStdout().trim();
        assertFalse(roleId.isEmpty());
        assertFalse(secretId.isEmpty());

        HashicorpVaultConfig cfg = config(Map.of());
        HashicorpVaultClient client = new HashicorpVaultClient(cfg);
        KeycloakSession session = FakeKeycloakSessions.create();
        client.writeSecret(session, ROOT_TOKEN, "it/approle-auth", "approle-value");

        AppRoleTokenProvider tokenProvider = new AppRoleTokenProvider(client, "approle", roleId, secretId);
        VaultSecretService service = new VaultSecretService(client, tokenProvider);

        assertEquals("approle-value", service.readSecret(session, "it/approle-auth").value());
        assertNotNull(tokenProvider.getToken(session), "AppRole login should have cached a client token");
    }

    // --- Retry behaviour and outage/recovery ---------------------------------------------------

    @Test
    void retriesAcrossATemporaryVaultOutageAndRecovers() throws Exception {
        KeycloakSession session = FakeKeycloakSessions.create();
        HashicorpVaultConfig writeCfg = config(Map.of());
        new HashicorpVaultClient(writeCfg).writeSecret(session, ROOT_TOKEN, "it/outage", "outage-value");

        // Generous retry budget: enough attempts/backoff to survive a short container pause.
        HashicorpVaultConfig cfg = config(Map.of(
                "retry-max-attempts", "6",
                "retry-initial-delay-ms", "300",
                "retry-max-delay-ms", "1000",
                "connect-timeout-ms", "500",
                "read-timeout-ms", "500"
        ));
        HashicorpVaultClient client = new HashicorpVaultClient(cfg);

        DockerClient dockerClient = DockerClientFactory.instance().client();
        dockerClient.pauseContainerCmd(vault.getContainerId()).exec();
        try {
            // Unpause shortly after the first attempt so the retry loop's later attempts succeed.
            new Thread(() -> {
                try {
                    Thread.sleep(600);
                } catch (InterruptedException ignored) {
                    Thread.currentThread().interrupt();
                } finally {
                    dockerClient.unpauseContainerCmd(vault.getContainerId()).exec();
                }
            }).start();

            HashicorpVaultClient.SecretLookup lookup = client.readSecret(session, ROOT_TOKEN, "it/outage");
            assertEquals("outage-value", lookup.value(), "read should eventually succeed once Vault recovers");
        } finally {
            try {
                dockerClient.unpauseContainerCmd(vault.getContainerId()).exec();
            } catch (Exception ignored) {
                // already unpaused
            }
        }
    }

    @Test
    void connectTimeoutFailsClosedWithoutHangingIndefinitely() {
        // A non-routable address (RFC 5737/TEST-NET style) to force a connect timeout rather than a refusal.
        HashicorpVaultConfig cfg = HashicorpVaultConfig.from(new MapScope(Map.of(
                "url", "http://192.0.2.1:8200",
                "connect-timeout-ms", "300",
                "read-timeout-ms", "300",
                "retry-max-attempts", "1"
        )));
        HashicorpVaultClient client = new HashicorpVaultClient(cfg);
        KeycloakSession session = FakeKeycloakSessions.create();

        long start = System.currentTimeMillis();
        HashicorpVaultClient.SecretLookup lookup = client.readSecret(session, ROOT_TOKEN, "it/unreachable");
        Duration elapsed = Duration.ofMillis(System.currentTimeMillis() - start);

        assertNull(lookup.value());
        assertTrue(elapsed.toSeconds() < 10, "a single attempt must fail closed quickly, took " + elapsed);
    }
}
