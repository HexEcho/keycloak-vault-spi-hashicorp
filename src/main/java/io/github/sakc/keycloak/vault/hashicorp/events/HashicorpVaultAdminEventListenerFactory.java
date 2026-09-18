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

import org.keycloak.Config;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventListenerProviderFactory;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.utils.KeycloakSessionUtil;

public class HashicorpVaultAdminEventListenerFactory implements EventListenerProviderFactory {

    public static final String PROVIDER_ID = "hashicorp-vault";

    @Override
    public EventListenerProvider create(KeycloakSession session) {
        return new HashicorpVaultAdminEventListener(session);
    }

    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        factory.register(event -> {
            if (event instanceof ClientModel.ClientCreationEvent creation) {
                ClientSecretVaultSync.sync(KeycloakSessionUtil.getKeycloakSession(), creation.getCreatedClient());
            } else if (event instanceof ClientModel.ClientUpdatedEvent updated) {
                ClientSecretVaultSync.sync(updated.getKeycloakSession(), updated.getUpdatedClient());
            }
        });
    }

    @Override
    public void close() {
    }

    @Override
    public boolean isGlobal() {
        return true;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
