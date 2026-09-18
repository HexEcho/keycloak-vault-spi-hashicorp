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

import com.fasterxml.jackson.databind.JsonNode;
import org.jboss.logging.Logger;

/**
 * Parses Vault auth/login JSON used by AppRole and TLS certificate methods.
 */
public final class VaultAuthTokens {

    private static final Logger log = Logger.getLogger(VaultAuthTokens.class);

    private VaultAuthTokens() {
    }

    public static ParsedToken parseLogin(JsonNode body) {
        if (body == null) {
            return null;
        }
        String token = body.path("auth").path("client_token").asText(null);
        if (token == null || token.isEmpty()) {
            log.error("Vault authentication response did not contain a client_token.");
            return null;
        }
        long leaseDuration = body.path("auth").path("lease_duration").asLong(0);
        return new ParsedToken(token, leaseDuration);
    }

    public record ParsedToken(String token, long leaseDurationSeconds) {
        public long expiresAtMs(long nowMs) {
            if (leaseDurationSeconds <= 0) {
                return Long.MAX_VALUE;
            }
            return nowMs + (long) (leaseDurationSeconds * 1000 * 0.9);
        }
    }
}
