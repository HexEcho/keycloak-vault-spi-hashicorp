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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class VaultRetryPolicyTest {

    @Test
    void firstAttemptHasNoBackoff() {
        VaultRetryPolicy policy = new VaultRetryPolicy(4, 100, 1000);
        assertEquals(0, policy.backoffDelayMs(1));
    }

    @Test
    void backoffDoublesAndIsCappedWithJitter() {
        VaultRetryPolicy policy = new VaultRetryPolicy(4, 100, 1000);
        long attempt2 = policy.backoffDelayMs(2);
        long attempt3 = policy.backoffDelayMs(3);
        long attempt4 = policy.backoffDelayMs(4);

        assertWithinJitter(100, attempt2);
        assertWithinJitter(200, attempt3);
        assertWithinJitter(400, attempt4);
    }

    @Test
    void backoffNeverExceedsMaxDelay() {
        VaultRetryPolicy policy = new VaultRetryPolicy(10, 100, 300);
        for (int attempt = 2; attempt <= 10; attempt++) {
            assertTrue(policy.backoffDelayMs(attempt) <= 300 * 1.2 + 1);
        }
    }

    @Test
    void shouldRetryRespectsMaxAttempts() {
        VaultRetryPolicy policy = new VaultRetryPolicy(3, 100, 1000);
        assertTrue(policy.shouldRetry(1));
        assertTrue(policy.shouldRetry(2));
        assertFalse(policy.shouldRetry(3));
    }

    @Test
    void maxAttemptsIsAtLeastOne() {
        VaultRetryPolicy policy = new VaultRetryPolicy(0, 100, 1000);
        assertEquals(1, policy.maxAttempts());
    }

    private static void assertWithinJitter(long base, long actual) {
        assertTrue(actual >= base * 0.8 - 1 && actual <= base * 1.2 + 1,
                "expected ~" + base + " (+/-20%) but was " + actual);
    }
}
