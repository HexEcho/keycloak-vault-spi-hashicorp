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
 * Base type for every error the {@code VaultClient} layer can raise. Messages are built from
 * the operation name, the HTTP status, and the Vault path only: never a token, secret value,
 * AppRole secret id, JWT, or private key.
 */
public class VaultException extends RuntimeException {

    private final String operation;
    private final String vaultPath;
    private final int httpStatus;

    public VaultException(String operation, String vaultPath, int httpStatus, String message) {
        this(operation, vaultPath, httpStatus, message, null);
    }

    public VaultException(String operation, String vaultPath, int httpStatus, String message, Throwable cause) {
        super(message, cause);
        this.operation = operation;
        this.vaultPath = vaultPath;
        this.httpStatus = httpStatus;
    }

    public String getOperation() {
        return operation;
    }

    public String getVaultPath() {
        return vaultPath;
    }

    /** HTTP status that produced this error, or {@code 0} when there was no HTTP response (connection/timeout). */
    public int getHttpStatus() {
        return httpStatus;
    }
}
