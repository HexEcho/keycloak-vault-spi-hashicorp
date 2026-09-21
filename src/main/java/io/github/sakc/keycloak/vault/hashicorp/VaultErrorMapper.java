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

import io.github.sakc.keycloak.vault.hashicorp.exception.VaultAuthenticationException;
import io.github.sakc.keycloak.vault.hashicorp.exception.VaultAuthorizationException;
import io.github.sakc.keycloak.vault.hashicorp.exception.VaultConfigurationException;
import io.github.sakc.keycloak.vault.hashicorp.exception.VaultConnectionException;
import io.github.sakc.keycloak.vault.hashicorp.exception.VaultException;
import io.github.sakc.keycloak.vault.hashicorp.exception.VaultRateLimitException;
import io.github.sakc.keycloak.vault.hashicorp.exception.VaultSecretNotFoundException;
import io.github.sakc.keycloak.vault.hashicorp.exception.VaultServerException;
import io.github.sakc.keycloak.vault.hashicorp.exception.VaultTimeoutException;

import java.io.InterruptedIOException;
import java.net.ConnectException;
import java.net.NoRouteToHostException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;

/**
 * Single place that turns a Vault HTTP status or transport failure into one of the typed
 * {@link VaultException} subclasses, and decides which of those are worth retrying.
 *
 * <p>Retry decision table:</p>
 * <pre>
 * 429, 500, 502, 503, 504, connect timeout, read timeout, connection reset/refused -> retry (bounded)
 * 400, 401, 403, 404, other 4xx, malformed/invalid configuration                   -> never retried
 * </pre>
 */
public final class VaultErrorMapper {

    private VaultErrorMapper() {
    }

    /** Login (authenticate) failures are surfaced as {@link VaultAuthenticationException}, not authorization ones. */
    public static VaultException mapLoginStatus(String vaultPath, int status) {
        return mapStatus("authenticate", vaultPath, status, true);
    }

    public static VaultException mapStatus(String operation, String vaultPath, int status) {
        return mapStatus(operation, vaultPath, status, false);
    }

    private static VaultException mapStatus(String operation, String vaultPath, int status, boolean isLogin) {
        return switch (status) {
            case 401 -> new VaultAuthenticationException(operation, vaultPath, status);
            case 403 -> isLogin ? new VaultAuthenticationException(operation, vaultPath, status)
                    : new VaultAuthorizationException(operation, vaultPath, status);
            case 404 -> new VaultSecretNotFoundException(operation, vaultPath, status);
            case 429 -> new VaultRateLimitException(operation, vaultPath, status);
            case 400 -> new VaultConfigurationException(operation, vaultPath, status);
            default -> status >= 500
                    ? new VaultServerException(operation, vaultPath, status)
                    : new VaultConfigurationException(operation, vaultPath, status);
        };
    }

    /** Transient HTTP statuses that are safe to retry with backoff. */
    public static boolean isRetryableStatus(int status) {
        return status == 429 || status == 500 || status == 502 || status == 503 || status == 504;
    }

    /**
     * Classifies a transport-level failure as a timeout or a connection problem. Both are
     * retryable while attempts remain; once exhausted the caller wraps the last one.
     */
    public static VaultException mapTransportFailure(String operation, String vaultPath, Exception e) {
        if (e instanceof SocketTimeoutException || e instanceof InterruptedIOException) {
            return new VaultTimeoutException(operation, vaultPath, e);
        }
        return new VaultConnectionException(operation, vaultPath, e);
    }

    /** Any transport-level exception (timeout, refused, reset, DNS) is treated as retryable. */
    public static boolean isRetryableTransportFailure(Exception e) {
        return e instanceof SocketTimeoutException
                || e instanceof InterruptedIOException
                || e instanceof ConnectException
                || e instanceof NoRouteToHostException
                || e instanceof UnknownHostException
                || e instanceof java.io.IOException;
    }
}
