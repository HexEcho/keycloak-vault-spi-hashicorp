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

import com.fasterxml.jackson.databind.JsonNode;
import org.jboss.logging.Logger;
import org.keycloak.http.simple.SimpleHttp;
import org.keycloak.http.simple.SimpleHttpRequest;
import org.keycloak.http.simple.SimpleHttpResponse;
import org.keycloak.models.KeycloakSession;
import org.keycloak.util.JsonSerialization;

import java.io.IOException;
import java.util.Map;

/**
 * HashiCorp KV HTTP calls using Keycloak {@link SimpleHttp} (HttpClientProvider).
 * Does not construct an HTTP client.
 */
public final class HashicorpVaultClient {

    private static final Logger log = Logger.getLogger(HashicorpVaultClient.class);

    private final HashicorpVaultConfig config;

    public HashicorpVaultClient(HashicorpVaultConfig config) {
        this.config = config;
    }

    public SecretLookup readSecret(KeycloakSession session, String token, String vaultKey) {
        String url = secretUrl(config, vaultKey);
        try (SimpleHttpResponse response = applyVaultHeaders(SimpleHttp.create(session)
                .doGet(url), token)
                .acceptJson()
                .asResponse()) {
            int status = response.getStatus();
            String body = response.asString();
            if (status == 404) {
                log.debugf("Secret not found in HashiCorp Vault for key %s", vaultKey);
                return new SecretLookup(status, null);
            }
            if (status == 403) {
                log.debugf("HashiCorp Vault returned 403 for key %s", vaultKey);
                return new SecretLookup(status, null);
            }
            if (status < 200 || status >= 300) {
                log.warnf("Failed to fetch secret from HashiCorp Vault for key %s. HTTP %d.", vaultKey, status);
                return new SecretLookup(status, null);
            }
            JsonNode root = JsonSerialization.mapper.readTree(body);
            String value = extractField(root, config.getKvVersion(), config.getKvField());
            if (value == null) {
                log.warnf("Vault response for key %s did not contain field '%s'.", vaultKey, config.getKvField());
            }
            return new SecretLookup(status, value);
        } catch (IOException e) {
            log.error("Error fetching secret from HashiCorp Vault.", e);
            return new SecretLookup(0, null);
        }
    }

    public WriteResult writeSecret(KeycloakSession session, String token, String vaultKey, String secret) {
        String url = secretUrl(config, vaultKey);
        try (SimpleHttpResponse response = applyVaultHeaders(SimpleHttp.create(session)
                .doPut(url), token)
                .json(writeBody(config, secret))
                .asResponse()) {
            int status = response.getStatus();
            if (status < 200 || status >= 300) {
                log.warnf("Failed to write secret to HashiCorp Vault for key %s. HTTP %d.", vaultKey, status);
            }
            return new WriteResult(status);
        } catch (IOException e) {
            log.error("Error writing secret to HashiCorp Vault.", e);
            return new WriteResult(0);
        }
    }

    public DeleteResult deleteSecret(KeycloakSession session, String token, String vaultKey) {
        String url = deleteUrl(config, vaultKey);
        try (SimpleHttpResponse response = applyVaultHeaders(SimpleHttp.create(session)
                .doDelete(url), token)
                .asResponse()) {
            int status = response.getStatus();
            if (status != 404 && (status < 200 || status >= 300)) {
                log.warnf("Failed to delete secret from HashiCorp Vault for key %s. HTTP %d.", vaultKey, status);
            }
            return new DeleteResult(status);
        } catch (IOException e) {
            log.error("Error deleting secret from HashiCorp Vault.", e);
            return new DeleteResult(0);
        }
    }

    public JsonNode login(KeycloakSession session, String loginPath, Map<String, String> body) throws IOException {
        String url = config.getUrl() + "/v1/" + stripLeadingSlash(loginPath);
        try (SimpleHttpResponse response = applyVaultHeaders(SimpleHttp.create(session)
                .doPost(url), null)
                .json(body)
                .asResponse()) {
            int status = response.getStatus();
            String responseBody = response.asString();
            if (status != 200) {
                log.errorf("Vault login failed. HTTP %d.", status);
                return null;
            }
            return JsonSerialization.mapper.readTree(responseBody);
        }
    }

    static String secretUrl(HashicorpVaultConfig config, String vaultKey) {
        StringBuilder url = new StringBuilder(config.getUrl())
                .append("/v1/")
                .append(config.getKvMount());
        if (config.getKvVersion() == 2) {
            url.append("/data/");
        } else {
            url.append('/');
        }
        return url.append(vaultKey).toString();
    }

    static String deleteUrl(HashicorpVaultConfig config, String vaultKey) {
        StringBuilder url = new StringBuilder(config.getUrl())
                .append("/v1/")
                .append(config.getKvMount());
        if (config.getKvVersion() == 2) {
            url.append("/metadata/");
        } else {
            url.append('/');
        }
        return url.append(vaultKey).toString();
    }

    SimpleHttpRequest applyVaultHeaders(SimpleHttpRequest request, String token) {
        if (token != null && !token.isEmpty()) {
            request = request.header("X-Vault-Token", token);
        }
        String namespace = config.getNamespace();
        if (namespace != null && !namespace.isEmpty()) {
            request = request.header("X-Vault-Namespace", namespace);
        }
        return request;
    }

    static Map<String, Object> writeBody(HashicorpVaultConfig config, String secret) {
        if (config.getKvVersion() == 2) {
            return Map.of("data", Map.of(config.getKvField(), secret));
        }
        return Map.of(config.getKvField(), secret);
    }

    static String extractField(JsonNode root, int kvVersion, String field) {
        if (root == null || field == null) {
            return null;
        }
        JsonNode data = kvVersion == 2 ? root.path("data").path("data") : root.path("data");
        JsonNode value = data.get(field);
        if (value == null || value.isMissingNode() || value.isNull()) {
            return null;
        }
        return value.asText();
    }

    private static String stripLeadingSlash(String path) {
        if (path == null || path.isEmpty()) {
            return path;
        }
        return path.charAt(0) == '/' ? path.substring(1) : path;
    }

    public record SecretLookup(int status, String value) {
        public boolean isForbidden() {
            return status == 403;
        }

        public boolean found() {
            return value != null && !value.isEmpty();
        }
    }

    public record WriteResult(int status) {
        public boolean success() {
            return status >= 200 && status < 300;
        }

        public boolean isForbidden() {
            return status == 403;
        }
    }

    public record DeleteResult(int status) {
        public boolean success() {
            return (status >= 200 && status < 300) || status == 404;
        }

        public boolean isForbidden() {
            return status == 403;
        }
    }
}
