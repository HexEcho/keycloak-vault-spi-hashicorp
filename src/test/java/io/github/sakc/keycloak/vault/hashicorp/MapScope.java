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

import org.keycloak.Config;

import java.util.Map;
import java.util.Set;

@SuppressWarnings("deprecation")
final class MapScope implements Config.Scope {

    private final Map<String, String> values;

    MapScope(Map<String, String> values) {
        this.values = values;
    }

    @Override
    public String get(String key) {
        return values.get(key);
    }

    @Override
    public String get(String key, String defaultValue) {
        return values.getOrDefault(key, defaultValue);
    }

    @Override
    public String[] getArray(String key) {
        String value = values.get(key);
        return value == null ? null : value.split(",");
    }

    @Override
    public Integer getInt(String key) {
        String value = values.get(key);
        return value == null ? null : Integer.valueOf(value);
    }

    @Override
    public Integer getInt(String key, Integer defaultValue) {
        String value = values.get(key);
        return value == null ? defaultValue : Integer.valueOf(value);
    }

    @Override
    public Long getLong(String key) {
        String value = values.get(key);
        return value == null ? null : Long.valueOf(value);
    }

    @Override
    public Long getLong(String key, Long defaultValue) {
        String value = values.get(key);
        return value == null ? defaultValue : Long.valueOf(value);
    }

    @Override
    public Boolean getBoolean(String key) {
        String value = values.get(key);
        return value == null ? null : Boolean.valueOf(value);
    }

    @Override
    public Boolean getBoolean(String key, Boolean defaultValue) {
        String value = values.get(key);
        return value == null ? defaultValue : Boolean.valueOf(value);
    }

    @Override
    public Config.Scope scope(String... path) {
        return this;
    }

    @Override
    public Set<String> getPropertyNames() {
        return values.keySet();
    }

    @Override
    public Config.Scope root() {
        return this;
    }
}
