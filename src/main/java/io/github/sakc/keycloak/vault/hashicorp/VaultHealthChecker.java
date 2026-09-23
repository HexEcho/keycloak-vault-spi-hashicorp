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

import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;

/**
 * Optional, low-frequency background poll of {@code GET /v1/sys/health}, purely for operational
 * diagnostics. Runs on its own daemon thread and is never on the path of a secret lookup, so it
 * cannot add latency or a hard dependency to normal Keycloak request handling.
 */
public final class VaultHealthChecker implements AutoCloseable {

    private static final Logger log = Logger.getLogger(VaultHealthChecker.class);

    private final ScheduledExecutorService executor;

    private VaultHealthChecker(ScheduledExecutorService executor) {
        this.executor = executor;
    }

    public static VaultHealthChecker start(KeycloakSessionFactory sessionFactory, HashicorpVaultClient client,
                                            HashicorpVaultConfig config) {
        ThreadFactory threadFactory = runnable -> {
            Thread thread = new Thread(runnable, "hashicorp-vault-health-check");
            thread.setDaemon(true);
            return thread;
        };
        ScheduledExecutorService executor = Executors.newSingleThreadScheduledExecutor(threadFactory);
        long intervalMs = config.getHealthCheckIntervalMs();
        executor.scheduleWithFixedDelay(() -> runCheck(sessionFactory, client), intervalMs, intervalMs,
                TimeUnit.MILLISECONDS);
        log.infof("Vault health check enabled. intervalMs=%d", intervalMs);
        return new VaultHealthChecker(executor);
    }

    private static void runCheck(KeycloakSessionFactory sessionFactory, HashicorpVaultClient client) {
        try (KeycloakSession session = sessionFactory.create()) {
            client.healthCheck(session);
        } catch (Exception e) {
            log.warn("Vault health check encountered an unexpected error.", e);
        }
    }

    @Override
    public void close() {
        executor.shutdownNow();
    }
}
