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

/**
 * Single place that builds and validates every Vault KV path used by this SPI
 * (realm-scoped lookups, managed confidential-client secrets, KV v1/v2 read/delete URLs).
 *
 * <p>Paths are never silently sanitized. A segment that fails validation causes the whole
 * operation to be rejected (throws {@link IllegalArgumentException}), so a malformed or
 * malicious realm/key can never be concatenated into a path that reaches another realm's
 * secrets or an unintended Vault location.</p>
 */
public final class VaultPathResolver {

    /** Default sub-path under a realm folder for secrets this SPI creates and owns. */
    public static final String DEFAULT_MANAGED_NAMESPACE = "managed";

    private VaultPathResolver() {
    }

    /**
     * A path segment (realm name, secret key, namespace, mount) is safe when it is non-blank,
     * contains no path traversal sequence, no NUL/control characters, no path separators at
     * the edges, and does not itself smuggle a separator that would change the path shape.
     */
    public static boolean isSafeSegment(String segment) {
        if (segment == null || segment.isEmpty()) {
            return false;
        }
        if (segment.trim().isEmpty()) {
            return false;
        }
        if (segment.contains("..")) {
            return false;
        }
        if (segment.startsWith("/") || segment.endsWith("/") || segment.startsWith("\\") || segment.endsWith("\\")) {
            return false;
        }
        for (int i = 0; i < segment.length(); i++) {
            char c = segment.charAt(i);
            if (Character.isISOControl(c)) {
                return false;
            }
        }
        return true;
    }

    /**
     * A fully resolved Vault key (realm + key already combined by a Keycloak key resolver)
     * is safe when every '/'-separated component is itself a safe segment and there is no
     * empty component from an accidental double separator.
     */
    public static boolean isSafeResolvedKey(String resolvedKey) {
        if (!isSafeSegment(resolvedKey)) {
            return false;
        }
        if (resolvedKey.contains("//") || resolvedKey.contains("\\\\")) {
            return false;
        }
        for (String part : resolvedKey.split("/", -1)) {
            if (!isSafeSegment(part)) {
                return false;
            }
        }
        return true;
    }

    /**
     * @throws IllegalArgumentException if the realm identifier is empty, blank, or contains
     *                                   path traversal / separator characters.
     */
    public static String requireSafeRealm(String realm) {
        if (!isSafeSegment(realm)) {
            throw new IllegalArgumentException("Refusing to resolve a Vault path for an invalid or empty realm identifier.");
        }
        return realm;
    }

    /**
     * @throws IllegalArgumentException if the secret key is empty, blank, or contains
     *                                   path traversal / separator characters.
     */
    public static String requireSafeKey(String key) {
        if (!isSafeSegment(key)) {
            throw new IllegalArgumentException("Refusing to resolve a Vault path for an invalid or empty secret key.");
        }
        return key;
    }

    /**
     * Builds the deterministic, realm-isolated path for a secret managed by this SPI
     * (as opposed to a secret an operator manages directly in Vault):
     * {@code <realm>/<managedNamespace>/<secretKey>}.
     *
     * <p>Realm A can never resolve to a path under realm B: the realm is always the first,
     * mandatory path segment and is validated independently of the secret key.</p>
     *
     * @param managedNamespace sub-path distinguishing SPI-managed secrets from externally
     *                         managed ones (for example {@code managed}); must not be blank
     */
    public static String managedKey(String realm, String managedNamespace, String secretKey) {
        requireSafeRealm(realm);
        requireSafeKey(secretKey);
        if (!isSafeSegment(managedNamespace)) {
            throw new IllegalArgumentException("Refusing to resolve a managed Vault path with an invalid namespace.");
        }
        String resolved = realm + "/" + managedNamespace + "/" + secretKey;
        if (!isSafeResolvedKey(resolved)) {
            throw new IllegalArgumentException("Resolved managed Vault key failed validation.");
        }
        return resolved;
    }

    /**
     * KV read/write URL: {@code <url>/v1/<mount>/data/<key>} for KV v2, {@code <url>/v1/<mount>/<key>} for KV v1.
     *
     * @throws IllegalArgumentException if {@code resolvedKey} is not a safe path
     */
    public static String secretUrl(HashicorpVaultConfig config, String resolvedKey) {
        requireSafeResolvedKeyForUrl(resolvedKey);
        StringBuilder url = new StringBuilder(config.getUrl())
                .append("/v1/")
                .append(config.getKvMount());
        if (config.getKvVersion() == 2) {
            url.append("/data/");
        } else {
            url.append('/');
        }
        return url.append(resolvedKey).toString();
    }

    /**
     * KV delete URL: KV v2 uses {@code metadata} (removes all versions), KV v1 uses the data path directly.
     *
     * @throws IllegalArgumentException if {@code resolvedKey} is not a safe path
     */
    public static String deleteUrl(HashicorpVaultConfig config, String resolvedKey) {
        requireSafeResolvedKeyForUrl(resolvedKey);
        StringBuilder url = new StringBuilder(config.getUrl())
                .append("/v1/")
                .append(config.getKvMount());
        if (config.getKvVersion() == 2) {
            url.append("/metadata/");
        } else {
            url.append('/');
        }
        return url.append(resolvedKey).toString();
    }

    private static void requireSafeResolvedKeyForUrl(String resolvedKey) {
        if (!isSafeResolvedKey(resolvedKey)) {
            throw new IllegalArgumentException("Refusing to build a Vault URL for an unsafe key.");
        }
    }
}
