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
package io.github.sakc.keycloak.vault.hashicorp.clientauth;

import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oidc.OIDCClientSecretConfigWrapper;
import org.keycloak.vault.VaultStringSecret;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * Resolves {@code ${vault.key}} the same way Keycloak 26.6 does for confidential clients.
 * Plaintext secrets still compare as themselves ({@code DefaultVaultTranscriber}).
 */
public final class ClientSecretVaultMatcher {

    private ClientSecretVaultMatcher() {
    }

    public static boolean matchesCurrent(KeycloakSession session, String storedSecret, String presentedSecret) {
        return constantTimeEquals(resolve(session, storedSecret), presentedSecret);
    }

    public static boolean matchesRotated(KeycloakSession session, OIDCClientSecretConfigWrapper wrapper,
                                          String presentedSecret) {
        if (!wrapper.hasRotatedSecret() || wrapper.isClientRotatedSecretExpired()) {
            return false;
        }
        return constantTimeEquals(resolve(session, wrapper.getClientRotatedSecret()), presentedSecret);
    }

    static String resolve(KeycloakSession session, String stored) {
        if (stored == null) {
            return null;
        }
        try (VaultStringSecret vaultSecret = session.vault().getStringSecret(stored)) {
            return vaultSecret.get().orElse(stored);
        }
    }

    static boolean constantTimeEquals(String expected, String presented) {
        if (expected == null || presented == null) {
            return false;
        }
        return MessageDigest.isEqual(expected.getBytes(StandardCharsets.UTF_8),
                presented.getBytes(StandardCharsets.UTF_8));
    }
}
