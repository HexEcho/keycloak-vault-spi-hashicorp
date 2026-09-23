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
 * The Vault token is valid but lacks permission for the requested path (HTTP 403).
 */
public class VaultAuthorizationException extends VaultException {

    public VaultAuthorizationException(String operation, String vaultPath, int httpStatus) {
        super(operation, vaultPath, httpStatus,
                "Vault denied permission for operation '" + operation + "' on path '" + vaultPath + "' (HTTP " + httpStatus + ")");
    }
}
