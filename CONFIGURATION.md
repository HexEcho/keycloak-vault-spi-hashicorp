# Configuration Reference

This document is the canonical property reference for the HashiCorp Vault SPI. All values below are read from the Keycloak provider configuration in the same naming pattern as the runtime configuration system.

## Global property reference

| Property | Type | Default | Required | Sensitive | Restart required | Description |
|---|---|---|---|---|---|---|
| url | string | http://127.0.0.1:8200 | Yes | No | Yes | Base URL for the Vault listener. Use `http` only for local testing; production should prefer `https`. |
| auth-method | enum | token | Yes | No | Yes | One of `token`, `approle`, `cert`, or `kubernetes`. |
| namespace | string | unset | No | No | Yes | Vault Enterprise namespace; sent as `X-Vault-Namespace` on each request. |
| token | string | unset | Only for token auth | Yes | Yes | Static Vault token. For production, prefer workload identities or AppRole/Kubernetes auth instead. |
| approle-role-id | string | unset | Yes for AppRole | Yes | Yes | Vault AppRole role ID. |
| approle-secret-id | string | unset | Yes for AppRole | Yes | Yes | Vault AppRole secret ID. |
| approle-mount-path | string | approle | No | No | Yes | AppRole auth mount path. |
| cert-name | string | unset | No for cert auth | No | Yes | TLS certificate auth role name in Vault. |
| cert-mount-path | string | cert | No | No | Yes | Vault TLS certificate auth mount. |
| kubernetes-role | string | unset | Yes for Kubernetes auth | No | Yes | Vault Kubernetes auth role name. |
| kubernetes-mount-path | string | kubernetes | No | No | Yes | Kubernetes auth mount path. |
| kubernetes-jwt-path | string | /var/run/secrets/kubernetes.io/serviceaccount/token | Yes for Kubernetes auth | No | Yes | Path to the service account JWT; read fresh for each login and never persisted. |
| managed-secret-prefix | string | unset | No | No | Yes | Optional namespace separating secrets this SPI manages from secrets created manually. |
| kv-mount | string | secret | Yes | No | Yes | Vault KV mount path. |
| kv-version | int | 2 | Yes | No | Yes | KV secrets engine version: `1` or `2`. |
| kv-field | string | value | Yes | No | Yes | Field inside the secret payload to read or write. |
| kv-read-version | int | unset | No | No | Yes | Optional KV v2 version to read. If unset, the latest version is read. |
| cache-enabled | boolean | true | No | No | Yes | Whether successful reads are cached in Keycloak’s local Infinispan cache. |
| cache-ttl | long ms | 300000 | No | No | Yes | Secret cache TTL in milliseconds. `0` disables the cache. |
| cache-max-entries | int | 10000 | No | No | Yes | Maximum number of cached entries in the node-local cache. |
| connect-timeout-ms | long ms | 2000 | No | No | Yes | HTTP connect timeout. |
| read-timeout-ms | long ms | 5000 | No | No | Yes | HTTP read timeout. |
| request-timeout-ms | long ms | 5000 | No | No | Yes | Maximum wait for a connection from the pool. |
| retry-max-attempts | int | 4 | No | No | Yes | Maximum attempts for retryable failures. |
| retry-initial-delay-ms | long ms | 100 | No | No | Yes | Initial retry delay. |
| retry-max-delay-ms | long ms | 1000 | No | No | Yes | Max retry delay. |
| health-check-enabled | boolean | false | No | No | Yes | Enable background Vault health checks. |
| health-check-interval-ms | long ms | 30000 | No | No | Yes | Delay between health probes. |
| key-resolvers | string | REALM_UNDERSCORE_KEY | No | No | Yes | Comma-separated Keycloak vault resolvers. Use `REALM_FILESEPARATOR_KEY` for realm-scoped layouts. |

## Production recommendation

- Use `https` for `url` in production.
- Prefer `auth-method=kubernetes` or `auth-method=cert` when the runtime is in Kubernetes or has a trusted mTLS identity.
- Keep `cache-enabled` false or `cache-ttl` short for high-sensitivity deployments.
- Use `managed-secret-prefix` to keep SPI-created secrets clearly isolated from operator-managed secrets.
- Use least-privilege Vault policy paths that restrict reads and writes to the relevant realm or tenant.

## Example configuration

### Development

```properties
spi-vault--provider=hashicorp
spi-vault--hashicorp--url=http://127.0.0.1:8200
spi-vault--hashicorp--auth-method=token
spi-vault--hashicorp--token=replace-with-debug-token
spi-vault--hashicorp--cache-enabled=true
spi-vault--hashicorp--cache-ttl=300000
```

### Production

```properties
spi-vault--provider=hashicorp
spi-vault--hashicorp--url=https://vault.internal.example.com
spi-vault--hashicorp--auth-method=kubernetes
spi-vault--hashicorp--kubernetes-role=keycloak-prod
spi-vault--hashicorp--kubernetes-mount-path=kubernetes
spi-vault--hashicorp--kv-mount=secret
spi-vault--hashicorp--kv-version=2
spi-vault--hashicorp--cache-enabled=false
spi-vault--hashicorp--retry-max-attempts=3
spi-vault--hashicorp--connect-timeout-ms=2000
spi-vault--hashicorp--read-timeout-ms=5000
spi-vault--hashicorp--request-timeout-ms=5000
```

See [SECURITY.md](SECURITY.md) for the cache, auth, and policy guidance. See [OPERATIONS.md](OPERATIONS.md) for retry and outage semantics.
