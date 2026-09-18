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

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class HashicorpVaultExpressionsTest {

    @Test
    void extractsVaultKeysFromAdminRepresentation() {
        String representation = "{\"bindCredential\":\"${vault.ldapBc}\",\"smtpPassword\":\"${vault.smtpPass}\"}";
        assertEquals(List.of("ldapBc", "smtpPass"), HashicorpVaultExpressions.extractKeys(representation));
    }

    @Test
    void returnsEmptyWhenNoVaultExpression() {
        assertTrue(HashicorpVaultExpressions.extractKeys("{\"secret\":\"plaintext\"}").isEmpty());
        assertTrue(HashicorpVaultExpressions.extractKeys(null).isEmpty());
    }

    @Test
    void detectsVaultPointer() {
        assertTrue(HashicorpVaultExpressions.isExpression("${vault.xyz}"));
        assertFalse(HashicorpVaultExpressions.isExpression("secret"));
        assertFalse(HashicorpVaultExpressions.isExpression(null));
        assertEquals("${vault.xyz}", HashicorpVaultExpressions.pointer("xyz"));
    }
}
