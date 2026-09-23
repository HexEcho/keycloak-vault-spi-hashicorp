# Keycloak Version Compatibility Risks

Supported baseline: Keycloak / RHBK **26.7.3** (see [pom.xml](pom.xml)). This document lists every Keycloak API this SPI depends on that is **internal, private, unstable, or otherwise not part of the public/stable extension SPI**, so future Keycloak upgrades can be scoped accurately instead of discovered by a broken build.

## Compatibility model

| Category | Value |
|---|---|
| Compile-time dependency | 26.7.3 |
| Tested runtime | 26.7.3 |
| Officially supported version | 26.7.3 |
| Legacy compatibility note | 26.4.x compatibility code paths are retained only as a bridge; they are not the supported baseline |

The project does not claim runtime support for a Keycloak version unless it is actually validated in the repository’s tests or in a documented runtime verification run. This is especially important for private APIs such as `SimpleHttp`, `InfinispanConnectionProvider`, and the built-in client-authenticator classes documented below.

Stability classes used below follow Keycloak's own convention:

* **Public SPI** — documented extension point (`org.keycloak.vault.*`, `org.keycloak.provider.*`
  service loader contracts). Expected to be stable across minor versions with deprecation notice.
* **Server-private SPI** (`keycloak-server-spi-private`, `keycloak-services`) — shipped as a
  Maven artifact but explicitly *not* covered by Keycloak's public API compatibility promise;
  used by Keycloak's own built-in providers and can change without a deprecation cycle.
  Not present in `keycloak-server-spi`.
* **Internal implementation detail** — package/class that exists to support Keycloak's own
  runtime and is not intended for extension authors at all.

## Dependency-by-dependency risk table

| API used | Keycloak artifact | Stability | Reason used | Compatibility risk |
|---|---|---|---|---|
| `org.keycloak.vault.AbstractVaultProvider` / `AbstractVaultProviderFactory` | `keycloak-server-spi` | Public SPI | Base classes for a Vault provider; gives us Keycloak's key-resolver chain for free | **Low.** This is the documented extension point for vault providers; Keycloak's own file/keystore vault providers extend the same classes. |
| `org.keycloak.vault.VaultProvider` / `VaultKeyResolver` / `VaultRawSecret` / `DefaultVaultRawSecret` | `keycloak-server-spi` | Public SPI | Return type contract for `obtainSecret` | **Low.** Stable public contract. |
| `org.keycloak.vault.VaultStringSecret` | `keycloak-server-spi` | Public SPI | Used by `ClientSecretVaultMatcher` to resolve `${vault.key}` the same way `DefaultVaultTranscriber` does | **Low.** |
| `org.keycloak.http.simple.SimpleHttp` / `SimpleHttpRequest` / `SimpleHttpResponse` | `keycloak-server-spi-private` | **Server-private SPI** | Avoids a second private HTTP client; reuses Keycloak's connection pool, proxy config, and TLS trust/keystore setup | **Medium.** This package was introduced in Keycloak 26.4 and is explicitly private (not in `keycloak-server-spi`). A future Keycloak release could rename, relocate, or replace it (Keycloak has done this before with `org.keycloak.broker.provider.util.SimpleHttp` → `org.keycloak.http.simple.SimpleHttp`). **This is the single highest-risk dependency in the codebase.** |
| `org.keycloak.authentication.authenticators.client.ClientIdAndSecretAuthenticator` / `ClientAuthUtil` | `keycloak-services` | **Server-private SPI / internal** | `VaultAwareClientIdAndSecretAuthenticator` extends Keycloak's built-in client-secret authenticator and overrides `order()` so it wins provider selection, adding `${vault.key}` resolution Keycloak 26.4 does not do at token time | **Medium-high.** Subclassing a built-in authenticator (rather than implementing `ClientAuthenticator` from scratch) inherits any internal behavior changes Keycloak makes to that class. A signature change to `ClientAuthenticationFlowContext` or the authenticator's internal helper methods would require a source-level fix. |
| `org.keycloak.connections.infinispan.InfinispanConnectionProvider` | `keycloak-model-infinispan` | **Server-private SPI** | Reuses Keycloak's embedded Infinispan cache manager instead of a private in-process cache | **Medium.** Infinispan cache wiring is an area Keycloak has restructured across major versions (the multi-site/embedded cache work is active). `HashicorpVaultCaches` isolates this to one class so a future change is a single-file fix. |
| `org.keycloak.spi.infinispan.impl.embedded.DefaultCacheEmbeddedConfigProviderFactory` | `keycloak-model-infinispan` | **Internal implementation detail** | Registers the `hashicorp-vault` cache in the embedded Infinispan configuration at boot, alongside Keycloak's own default caches | **High.** This is the deepest package used in this codebase (`org.keycloak.spi.infinispan.impl.*`) and is explicitly an implementation package, not a documented SPI. It exists only to let `HashicorpVaultCacheConfigProviderFactory` register a cache definition before first use; `HashicorpVaultCaches.defineLocalCache` is designed to degrade gracefully (define the cache lazily) if this optional factory is absent or its API changes. |
| `org.keycloak.events.EventListenerProvider` / `EventListenerProviderFactory` / `AdminEvent` / `Event` | `keycloak-server-spi` | Public SPI | Global admin/event listener for confidential-client secret write-back and cache invalidation | **Low.** Stable, widely used public SPI. |
| `org.keycloak.utils.KeycloakSessionUtil` | `keycloak-services` | **Server-private SPI** | Retrieves the current `KeycloakSession` inside `ClientModel.ClientCreationEvent` / `ClientUpdatedEvent` callbacks, which do not receive a session parameter | **Medium.** A small, single-purpose utility; low surface area, but not part of the public SPI. |
| `org.keycloak.models.ClientModel.ClientCreationEvent` / `ClientUpdatedEvent` | `keycloak-server-spi` | Public SPI (model event listeners) | Catches client secret regenerate immediately, since Keycloak 26.4 admin events alone were insufficient for the regenerate flow | **Low-medium.** Public interface, but the exact firing order/timing relative to `AdminEvent` has changed between Keycloak versions before. |
| `org.keycloak.util.JsonSerialization` | `keycloak-server-spi` (re-exported) | Public SPI | Vault JSON request/response bodies, avoiding a private Jackson dependency | **Low.** Long-stable utility class. |
| `org.keycloak.protocol.oidc.OIDCClientSecretConfigWrapper` | `keycloak-server-spi` | Public SPI | Reads the stored (possibly rotated) client secret the same way Keycloak's own OIDC code does | **Low.** |

## Overall risk concentration

The compatibility-sensitive surface is **intentionally concentrated in a small number of
files** so a Keycloak upgrade only requires auditing those:

* `HashicorpVaultClient` — the only class that touches `SimpleHttp`.
* `VaultAwareClientIdAndSecretAuthenticator` — the only class that extends a built-in authenticator.
* `cache/HashicorpVaultCaches` and `cache/HashicorpVaultCacheConfigProviderFactory` — the only classes that touch Infinispan wiring, and the cache-config factory is optional (registration failure only means the cache is defined lazily instead of at boot).
* `events/HashicorpVaultAdminEventListenerFactory` — the only class that uses `KeycloakSessionUtil`.

No other class in the codebase imports a `keycloak-server-spi-private`, `keycloak-services`,
or `keycloak-model-infinispan` type. Everything else (`VaultSecretService`,
`VaultPathResolver`, `VaultRetryPolicy`, `VaultErrorMapper`, the `exception/*` hierarchy, and
`HashicorpVaultConfig`) has **zero** Keycloak API dependency and is plain Java, which is why
it is fully unit-testable without a running Keycloak instance.

## Recommendations for future Keycloak upgrades

1. When bumping `keycloak.version`, recompile first and treat any compile error in the four
   files above as expected work, not a surprise; everything else should be a drop-in rebuild.
2. Before adopting a new Keycloak minor version in production, re-run the full test suite
   (`mvn verify`, including the Testcontainers integration tests) against a Keycloak instance
   built with that version, since `SimpleHttp` and the Infinispan cache SPI are the packages
   most likely to move.
3. If `org.keycloak.spi.infinispan.impl.embedded.DefaultCacheEmbeddedConfigProviderFactory`
   is removed or renamed in a future release, `HashicorpVaultCacheConfigProviderFactory` can
   simply be deleted — `HashicorpVaultCaches.defineLocalCache` already handles the case where
   the cache was not pre-registered at boot.
4. Keycloak 26.6+ resolves `${vault.key}` for confidential client secrets at token time
   without help; if this SPI ever drops support for 26.4, `VaultAwareClientIdAndSecretAuthenticator`
   and `ClientSecretVaultMatcher` become unnecessary and can be removed, eliminating the
   highest-risk authenticator-subclassing dependency entirely.
