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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Extracts Keycloak vault expression keys ({@code ${vault.key}}) from admin event representations.
 * Matches {@code DefaultVaultTranscriber}'s {@code ${vault.*}} form.
 */
public final class HashicorpVaultExpressions {

    private static final Pattern VAULT_EXPRESSION = Pattern.compile("\\$\\{vault\\.([^}]+)}");

    private HashicorpVaultExpressions() {
    }

    public static boolean isExpression(String value) {
        return value != null && value.startsWith("${vault.") && value.endsWith("}");
    }

    public static String pointer(String key) {
        return "${vault." + key + "}";
    }

    public static List<String> extractKeys(String representation) {
        if (representation == null || !representation.contains("${vault.")) {
            return Collections.emptyList();
        }
        Matcher matcher = VAULT_EXPRESSION.matcher(representation);
        List<String> keys = new ArrayList<>();
        while (matcher.find()) {
            String key = matcher.group(1);
            if (key != null && !key.isBlank()) {
                keys.add(key);
            }
        }
        return keys;
    }
}
