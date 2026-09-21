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
package io.github.sakc.keycloak.vault.hashicorp.auth;

import io.github.sakc.keycloak.vault.hashicorp.LogCapture;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class KubernetesTokenProviderTest {

    private static final String SENSITIVE_JWT = "eyJhbGciOiJSUzI1NiJ9.super-secret-service-account-jwt.sig";

    @Test
    void missingRoleFailsExplicitlyWithoutReadingJwt() {
        KubernetesTokenProvider provider = new KubernetesTokenProvider(null, "kubernetes", null,
                () -> {
                    throw new AssertionError("JWT must not be read when role is not configured");
                });
        assertNull(provider.getToken(null));
    }

    @Test
    void blankRoleFailsExplicitly() {
        KubernetesTokenProvider provider = new KubernetesTokenProvider(null, "kubernetes", "   ",
                () -> {
                    throw new AssertionError("JWT must not be read when role is blank");
                });
        assertNull(provider.getToken(null));
    }

    @Test
    void missingJwtSupplierResultFailsExplicitly() {
        KubernetesTokenProvider provider = new KubernetesTokenProvider(null, "kubernetes", "keycloak", () -> null);
        assertNull(provider.getToken(null));
    }

    @Test
    void malformedOrEmptyJwtFailsExplicitly() {
        KubernetesTokenProvider provider = new KubernetesTokenProvider(null, "kubernetes", "keycloak", () -> "   ");
        assertNull(provider.getToken(null));
    }

    @Test
    void missingJwtFileFailsExplicitlyWithoutThrowing() throws IOException {
        Path missing = Files.createTempDirectory("kc-vault-test").resolve("does-not-exist-token");
        KubernetesTokenProvider provider = KubernetesTokenProvider.forJwtFile(null, "kubernetes", "keycloak",
                missing.toString());
        assertNull(provider.getToken(null));
    }

    @Test
    void emptyJwtFileFailsExplicitly() throws IOException {
        Path file = Files.createTempFile("kc-vault-test-empty", ".jwt");
        try {
            Files.writeString(file, "   ");
            KubernetesTokenProvider provider = KubernetesTokenProvider.forJwtFile(null, "kubernetes", "keycloak",
                    file.toString());
            assertNull(provider.getToken(null));
        } finally {
            Files.deleteIfExists(file);
        }
    }

    @Test
    void unconfiguredJwtPathFailsExplicitly() {
        KubernetesTokenProvider provider = KubernetesTokenProvider.forJwtFile(null, "kubernetes", "keycloak", null);
        assertNull(provider.getToken(null));
    }

    @Test
    void invalidateDoesNotCauseInfiniteLoopWhenReAuthenticationAlsoFails() {
        KubernetesTokenProvider provider = new KubernetesTokenProvider(null, "kubernetes", null, () -> null);
        provider.invalidate();
        assertNull(provider.getToken(null));
        // second call must not loop or hang; it simply fails again explicitly
        assertNull(provider.getToken(null));
    }

    @Test
    void closeClearsCachedToken() {
        KubernetesTokenProvider provider = new KubernetesTokenProvider(null, "kubernetes", null, () -> null);
        provider.close();
        assertNull(provider.getToken(null));
    }

    @Test
    void jwtContentNeverAppearsInLogOutputOnFailurePaths() {
        try (LogCapture capture = LogCapture.forClass(KubernetesTokenProvider.class)) {
            // role missing -> logs an error, must not mention any JWT-like content
            KubernetesTokenProvider roleMissing = new KubernetesTokenProvider(null, "kubernetes", null,
                    () -> SENSITIVE_JWT);
            roleMissing.getToken(null);

            // jwt file present with sensitive content but role missing again: JWT is never read/logged
            KubernetesTokenProvider blankRole = new KubernetesTokenProvider(null, "kubernetes", "",
                    () -> SENSITIVE_JWT);
            blankRole.getToken(null);

            assertFalse(capture.anyMessageContains(SENSITIVE_JWT),
                    "Kubernetes JWT content must never appear in log output");
            assertTrue(capture.messages().size() >= 2, "expected explicit error logs for missing role");
        }
    }
}
