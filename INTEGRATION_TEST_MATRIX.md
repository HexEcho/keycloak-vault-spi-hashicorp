# Integration Test Matrix

This matrix maps the scenarios requested for the Vault integration to where they are
actually verified: unit tests (fast, no Docker), the Testcontainers suite
(`VaultContainerIT`, real HashiCorp Vault via Docker), or documented as not
feasible/needed in an automated, production-independent CI pipeline.

| Scenario | Covered by | Notes |
|---|---|---|
| KV v1 | `VaultContainerIT.kvV1WriteAndRead` + `HashicorpVaultClientTest` (URL/body shape) | Real KV v1 mount created in `@BeforeAll`. |
| KV v2 | `VaultContainerIT.kvV2WriteReadRotateAndDelete` / `kvV2VersionedReadReturnsThePinnedVersionNotLatest` + `HashicorpVaultClientTest` | Covers latest-version and pinned-version reads against a real KV v2 mount. |
| Token authentication | `VaultContainerIT.tokenAuthenticationReadsASecret` + `HashicorpVaultConfigTest`/`HashicorpVaultProviderFactoryTest` (config wiring) | |
| AppRole authentication | `VaultContainerIT.appRoleAuthenticationLogsInAndReadsASecret` + `AppRoleAuthStampedeTest` (concurrency) | Role/secret-id generated fresh against the running container in the test. |
| Kubernetes authentication | `KubernetesTokenProviderTest` (unit, fake JWT file + `FakeVaultServer`) | **Not run against a real Vault in CI**: Vault's Kubernetes auth method requires a live Kubernetes API server to validate the service-account JWT, which is out of scope for a Docker-only CI job. The HTTP request/response contract is exercised against a scripted fake server instead. |
| TLS / cert authentication | `CertTokenProviderTest`-style coverage via unit tests, `HashicorpVaultConfig` alias tests | **Not run against a real Vault in CI**: cert auth depends on Keycloak's own outbound HTTP client keystore (see [README](README.md#d-tls--certificate)), which this repository cannot provision without a full Keycloak runtime. Login request shape is unit-tested. |
| Vault namespace | Not integration-tested | Vault Enterprise namespaces require an Enterprise license; the OSS `hashicorp/vault` Testcontainers image cannot exercise this. `HashicorpVaultClient.applyVaultHeaders` sending `X-Vault-Namespace` is covered by unit tests. |
| Realm isolation | `HashicorpVaultCacheKeyTest`, `ClientSecretVaultSyncTest`, `VaultPathResolverTest` | Cache-key and path-resolution isolation between realms is deterministic and fully unit-testable without Vault or Keycloak. |
| Secret read | `VaultContainerIT` (all KV tests) | |
| Secret write | `VaultContainerIT` (all KV tests) | |
| Secret delete | `VaultContainerIT.kvV2WriteReadRotateAndDelete` | |
| Secret rotation | `VaultContainerIT.kvV2WriteReadRotateAndDelete` / `kvV2VersionedReadReturnsThePinnedVersionNotLatest` | Writes two versions, confirms latest vs. pinned reads. |
| Cache | `HashicorpVaultCacheKeyTest` | Cache-key composition (realm + mount + path + field + version) is pure-Java and fully unit-tested. |
| Cache invalidation | `ClientSecretVaultSyncTest`, `HashicorpVaultAdminEventListenerTest` | Invalidation triggers on write/delete/admin-event are unit-tested against a fake cache; a full Infinispan-backed invalidation test would require a running Keycloak server and is out of scope for this repository's test suite. |
| Token expiration | `VaultAuthTokensTest`, `AppRoleAuthStampedeTest` | Lease-duration parsing and the 90%-of-lease refresh window are deterministic and unit-tested; `VaultContainerIT.appRoleAuthenticationLogsInAndReadsASecret` confirms a real login populates a usable token. |
| Retry behavior | `HashicorpVaultClientRetryTest` (all status codes / transport errors) + `VaultRetryPolicyTest` | Exhaustive unit coverage of retryable vs. non-retryable status codes and backoff math. |
| Timeout behavior | `VaultContainerIT.connectTimeoutFailsClosedWithoutHangingIndefinitely` + `HashicorpVaultClientRetryTest` | Real connect-timeout against a non-routable address, confirming the client fails closed within the configured bound rather than hanging. |
| Vault outage / recovery | `VaultContainerIT.retriesAcrossATemporaryVaultOutageAndRecovers` | Pauses the real Vault container mid-test via the Docker API, then unpauses it, and asserts the retrying client's read still succeeds once Vault is reachable again. |

## Why Testcontainers, and why some scenarios stay at the unit level

* Real Vault semantics (KV envelope shape, versioning, error codes, lease format) are best
  verified against an actual Vault binary rather than re-implemented assumptions in a fake
  server. `VaultContainerIT` does exactly that with `hashicorp/vault` dev-mode containers.
* Kubernetes auth, cert auth, and Enterprise namespaces each require infrastructure this
  repository cannot stand up hermetically (a Kubernetes API server, a full Keycloak runtime
  with its own outbound TLS keystore, or a Vault Enterprise license). Testing the HTTP
  request/response contract for these with a scripted fake server (`FakeVaultServer`) is the
  practical boundary; it exercises every line of the request-building and response-parsing
  code without requiring infrastructure the CI job cannot provide.
* All integration tests in `VaultContainerIT` are skipped automatically
  (`org.junit.jupiter.api.Assumptions.assumeTrue`) when Docker is unavailable, so `mvn test`
  never depends on Docker and `mvn verify` degrades gracefully instead of failing hard in a
  Docker-less environment.
