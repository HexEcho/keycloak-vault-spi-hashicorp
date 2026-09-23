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
 * No secret exists at the requested Vault path (HTTP 404). This is an expected, non-retryable
 * outcome, not an operational failure.
 */
public class VaultSecretNotFoundException extends VaultException {

    public VaultSecretNotFoundException(String operation, String vaultPath, int httpStatus) {
        super(operation, vaultPath, httpStatus, "No secret found at Vault path '" + vaultPath + "'");
    }
}
