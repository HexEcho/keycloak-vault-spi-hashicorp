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
import org.junit.jupiter.api.Test;
import org.keycloak.util.JsonSerialization;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class VaultAuthTokensTest {

    @Test
    void parsesClientTokenAndLease() throws IOException {
        JsonNode body = JsonSerialization.mapper.readTree("""
                {"auth":{"client_token":"s.abc","lease_duration":3600}}
                """);
        VaultAuthTokens.ParsedToken parsed = VaultAuthTokens.parseLogin(body);
        assertEquals("s.abc", parsed.token());
        assertEquals(3600, parsed.leaseDurationSeconds());
        assertEquals(1000L + 3_240_000L, parsed.expiresAtMs(1000L));
    }

    @Test
    void returnsNullWhenClientTokenMissing() throws IOException {
        JsonNode body = JsonSerialization.mapper.readTree("{\"auth\":{}}");
        assertNull(VaultAuthTokens.parseLogin(body));
        assertNull(VaultAuthTokens.parseLogin(null));
    }
}
