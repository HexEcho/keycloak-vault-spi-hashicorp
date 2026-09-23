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
package io.github.sakc.keycloak.vault.hashicorp.exception;

/**
 * Vault rejected the request as malformed (HTTP 400), or the SPI/Vault configuration itself
 * (path, mount, kv-version, credentials) is invalid. Never retried.
 */
public class VaultConfigurationException extends VaultException {

    public VaultConfigurationException(String operation, String vaultPath, int httpStatus) {
        super(operation, vaultPath, httpStatus,
                "Vault rejected operation '" + operation + "' as malformed or misconfigured (HTTP " + httpStatus + ")");
    }

    public VaultConfigurationException(String message) {
        super(null, null, 0, message);
    }
}
