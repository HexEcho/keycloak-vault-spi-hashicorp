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

import org.junit.jupiter.api.Test;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.events.admin.OperationType;
import org.keycloak.events.admin.ResourceType;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ClientSecretVaultSyncTest {

    @Test
    void extractsClientUuidFromAdminResourcePath() {
        assertEquals("1a1deb7b-e21e-4852-b1f2-c7680c783459",
                ClientSecretVaultSync.clientUuidFromPath("clients/1a1deb7b-e21e-4852-b1f2-c7680c783459"));
        assertEquals("1a1deb7b-e21e-4852-b1f2-c7680c783459",
                ClientSecretVaultSync.clientUuidFromPath(
                        "admin/realms/demo/clients/1a1deb7b-e21e-4852-b1f2-c7680c783459/client-secret"));
        assertNull(ClientSecretVaultSync.clientUuidFromPath("roles/abc"));
        assertNull(ClientSecretVaultSync.clientUuidFromPath(null));
    }

    @Test
    void detectsClientSecretRegeneratePath() {
        assertTrue(ClientSecretVaultSync.isClientSecretPath("clients/uuid/client-secret"));
        assertFalse(ClientSecretVaultSync.isClientSecretPath("clients/uuid/client-secret/rotated"));
        assertFalse(ClientSecretVaultSync.isClientSecretPath("clients/uuid/registration-access-token"));
    }

    @Test
    void handlesCreateUpdateAndSecretAction() {
        assertTrue(ClientSecretVaultSync.isClientSecretAdminEvent(event(ResourceType.CLIENT, OperationType.CREATE,
                "clients/uuid")));
        assertTrue(ClientSecretVaultSync.isClientSecretAdminEvent(event(ResourceType.CLIENT, OperationType.UPDATE,
                "clients/uuid")));
        assertTrue(ClientSecretVaultSync.isClientSecretAdminEvent(event(ResourceType.CLIENT, OperationType.ACTION,
                "clients/uuid/client-secret")));
        assertFalse(ClientSecretVaultSync.isClientSecretAdminEvent(event(ResourceType.CLIENT, OperationType.ACTION,
                "clients/uuid/registration-access-token")));
        assertFalse(ClientSecretVaultSync.isClientSecretAdminEvent(event(ResourceType.REALM, OperationType.CREATE,
                "clients/uuid")));
        assertFalse(ClientSecretVaultSync.isClientSecretAdminEvent(event(ResourceType.CLIENT, OperationType.DELETE,
                "clients/uuid")));
        assertTrue(ClientSecretVaultSync.isClientSecretAdminEvent(event(null, OperationType.ACTION,
                "clients/uuid/client-secret")));
    }

    @Test
    void identifiesClientDeletion() {
        assertTrue(ClientSecretVaultSync.isClientDeletionAdminEvent(event(ResourceType.CLIENT, OperationType.DELETE,
                "clients/uuid")));
        assertFalse(ClientSecretVaultSync.isClientDeletionAdminEvent(event(ResourceType.REALM, OperationType.DELETE,
                "clients/uuid")));
    }

    private static AdminEvent event(ResourceType type, OperationType operation, String path) {
        AdminEvent event = new AdminEvent();
        if (type != null) {
            event.setResourceType(type);
        }
        event.setOperationType(operation);
        event.setResourcePath(path);
        return event;
    }
}
