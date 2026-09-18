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
package io.github.sakc.keycloak.vault.hashicorp.events;

import io.github.sakc.keycloak.vault.hashicorp.HashicorpVaultExpressions;
import io.github.sakc.keycloak.vault.hashicorp.cache.HashicorpVaultCaches;
import org.infinispan.Cache;
import org.jboss.logging.Logger;
import org.keycloak.events.Event;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;

import java.io.File;
import java.util.List;

/**
 * Writes generated confidential-client secrets to HashiCorp Vault, then invalidates cache when
 * {@code ${vault.key}} pointers change.
 */
public class HashicorpVaultAdminEventListener implements EventListenerProvider {

    private static final Logger log = Logger.getLogger(HashicorpVaultAdminEventListener.class);

    private final KeycloakSession session;

    public HashicorpVaultAdminEventListener(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public void onEvent(Event event) {
    }

    @Override
    public void onEvent(AdminEvent event, boolean includeRepresentation) {
        if (event == null) {
            return;
        }
        ClientSecretVaultSync.syncFromAdminEvent(session, event);
        invalidateVaultPointers(event);
    }

    @Override
    public void close() {
    }

    private void invalidateVaultPointers(AdminEvent event) {
        List<String> keys = HashicorpVaultExpressions.extractKeys(event.getRepresentation());
        if (keys.isEmpty()) {
            return;
        }
        Cache<String, String> cache = HashicorpVaultCaches.get(session);
        if (cache == null) {
            return;
        }
        String realmName = realmName(event.getRealmId());
        for (String key : keys) {
            cache.remove(key);
            if (realmName != null) {
                cache.remove(escape(realmName) + "_" + escape(key));
                cache.remove(realmName + File.separator + key);
            }
            log.debugf("Invalidated HashiCorp vault cache entries for key %s", key);
        }
    }

    private String realmName(String realmId) {
        if (realmId == null) {
            return null;
        }
        RealmModel realm = session.realms().getRealm(realmId);
        return realm == null ? null : realm.getName();
    }

    static String escape(String value) {
        return value.replace("_", "__");
    }
}
