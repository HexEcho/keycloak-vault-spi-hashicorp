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

import java.util.concurrent.ThreadLocalRandom;

/**
 * Bounded exponential backoff with jitter for Vault HTTP retries.
 *
 * <p>Delay before retry attempt {@code n} (n &gt;= 2, attempt 1 is always immediate):</p>
 * <pre>
 * delay(n) = min(maxDelayMs, initialDelayMs * 2^(n-2))   +/- 20% jitter
 * </pre>
 * With the defaults (initial=100ms, max=1000ms) this gives attempt 2 ~100ms, attempt 3 ~200ms,
 * attempt 4 ~400ms, capped at 1000ms for any later attempt.
 */
public final class VaultRetryPolicy {

    private final int maxAttempts;
    private final long initialDelayMs;
    private final long maxDelayMs;

    public VaultRetryPolicy(int maxAttempts, long initialDelayMs, long maxDelayMs) {
        this.maxAttempts = Math.max(1, maxAttempts);
        this.initialDelayMs = Math.max(0, initialDelayMs);
        this.maxDelayMs = Math.max(this.initialDelayMs, maxDelayMs);
    }

    public int maxAttempts() {
        return maxAttempts;
    }

    /**
     * @param attempt the attempt number that just failed (1-based)
     * @return whether another attempt should be made
     */
    public boolean shouldRetry(int attempt) {
        return attempt < maxAttempts;
    }

    /**
     * @param nextAttempt the attempt number about to be made (2-based; attempt 1 has no delay)
     * @return backoff delay in milliseconds, with +/-20% jitter
     */
    public long backoffDelayMs(int nextAttempt) {
        if (nextAttempt <= 1) {
            return 0;
        }
        long exponentialDelay = initialDelayMs * (1L << Math.min(20, nextAttempt - 2));
        long delay = Math.min(maxDelayMs, exponentialDelay);
        if (delay <= 0) {
            return 0;
        }
        double jitterFactor = 0.8 + (ThreadLocalRandom.current().nextDouble() * 0.4); // 0.8x - 1.2x
        return Math.max(0, Math.round(delay * jitterFactor));
    }
}
