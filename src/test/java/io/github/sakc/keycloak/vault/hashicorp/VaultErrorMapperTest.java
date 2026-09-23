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
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.net.ConnectException;
import java.net.SocketTimeoutException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

class VaultErrorMapperTest {

    @Test
    void mapsEachStatusToItsDocumentedExceptionType() {
        assertInstanceOf(VaultAuthenticationException.class, VaultErrorMapper.mapStatus("op", "p", 401));
        assertInstanceOf(VaultAuthorizationException.class, VaultErrorMapper.mapStatus("op", "p", 403));
        assertInstanceOf(VaultSecretNotFoundException.class, VaultErrorMapper.mapStatus("op", "p", 404));
        assertInstanceOf(VaultRateLimitException.class, VaultErrorMapper.mapStatus("op", "p", 429));
        assertInstanceOf(VaultConfigurationException.class, VaultErrorMapper.mapStatus("op", "p", 400));
        assertInstanceOf(VaultServerException.class, VaultErrorMapper.mapStatus("op", "p", 500));
        assertInstanceOf(VaultServerException.class, VaultErrorMapper.mapStatus("op", "p", 503));
    }

    @Test
    void loginFailuresAreAlwaysAuthenticationFailuresNeverAuthorization() {
        VaultException e = VaultErrorMapper.mapLoginStatus("auth/approle/login", 403);
        assertInstanceOf(VaultAuthenticationException.class, e);
    }

    @ParameterizedTest
    @ValueSource(ints = {429, 500, 502, 503, 504})
    void retryableStatusesAreMarkedRetryable(int status) {
        assertTrue(VaultErrorMapper.isRetryableStatus(status));
    }

    @ParameterizedTest
    @ValueSource(ints = {400, 401, 403, 404})
    void nonRetryableStatusesAreNeverRetried(int status) {
        assertFalse(VaultErrorMapper.isRetryableStatus(status));
    }

    @Test
    void socketTimeoutMapsToTimeoutException() {
        VaultException e = VaultErrorMapper.mapTransportFailure("read-secret", "p", new SocketTimeoutException("Read timed out"));
        assertInstanceOf(VaultTimeoutException.class, e);
    }

    @Test
    void connectExceptionMapsToConnectionException() {
        VaultException e = VaultErrorMapper.mapTransportFailure("read-secret", "p", new ConnectException("Connection refused"));
        assertInstanceOf(VaultConnectionException.class, e);
    }

    @Test
    void exceptionMessagesNeverContainTheWordToken() {
        VaultException e = VaultErrorMapper.mapStatus("read-secret", "demo/app", 403);
        assertFalse(e.getMessage().toLowerCase().contains("token=") , "must not leak a token value");
    }

    @Test
    void httpStatusIsPreservedOnTheException() {
        VaultException e = VaultErrorMapper.mapStatus("read-secret", "demo/app", 429);
        assertEquals(429, e.getHttpStatus());
        assertEquals("demo/app", e.getVaultPath());
        assertEquals("read-secret", e.getOperation());
    }
}
