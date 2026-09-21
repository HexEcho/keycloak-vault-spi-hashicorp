# Security Hardening

## Secret cache handling

The SPI caches Vault secret values in Keycloak’s embedded Infinispan cache. Those entries contain secret material and therefore must be treated as sensitive runtime data.

### Risks

- JVM heap exposure through memory dumps or crash analysis
- heap dump and crash dump leakage
- debugging or profiling tools exposing process memory
- memory scraping in a compromised container or host
- any node compromise giving access to the open heap

### Security defaults

- `cache-enabled` defaults to `true`, but a production deployment should prefer `false` or a short TTL unless there is a concrete operational reason to cache.
- `cache-ttl` should be short in security-sensitive deployments; long TTL values are appropriate only when the operational benefit outweighs the secret-exposure risk.
- `cache-max-entries` bounds cache growth so the cache cannot grow without limitation.
- Cache keys are realm-, mount-, path-, field-, and version-aware to reduce cross-contamination.

### Recommended settings

| Scenario | Recommendation |
|---|---|
| Maximum secret minimization | Set `cache-enabled=false` |
| Security-sensitive production | `cache-enabled=true`, `cache-ttl` short, e.g. 30-300s |
| Operationally justified caching | `cache-enabled=true`, bounded `cache-max-entries` and a documented TTL |

Never assume that the cache is encrypted; it is still in-process memory and subject to heap exposure.

## Authentication methods

| Method | Classification | Notes |
|---|---|---|
| token | Acceptable with controls | Suitable for controlled non-production or emergency use only; static tokens are easy to leak. |
| approle | Preferred for production | Better than static tokens in most cases, but the role ID and secret ID are still sensitive. |
| kubernetes | Preferred for production | Best suited for pod identity in Kubernetes when the runtime is inside the cluster. |
| cert | Preferred for production | Strong choice when the environment supports Vault TLS client cert authentication. |

### Production guidance

- Prefer workload identity over static secrets.
- Do not commit Vault tokens, AppRole IDs, AppRole secret IDs, or Kubernetes service account JWTs to source control, config maps, Docker images, or logs.
- Treat Kubernetes JWTs as extremely short-lived, ephemeral credentials; they are read fresh and never cached by the provider.
- If a static token must be used, keep it in a secret manager or Kubernetes secret and rotate it regularly.

## Vault policy guidance

Vault policies should follow least privilege. Keep read and write scopes restricted to specific realms or tenants rather than `/*` or mount-wide wildcard access.

A useful pattern is:

```hcl
path "secret/data/<realm>/*" {
  capabilities = ["read"]
}

path "secret/data/<realm>/<managed-secret-prefix>/*" {
  capabilities = ["create", "update", "read", "delete"]
}
```

Do not grant broad delete access unless the operator intentionally wants deletion at the path scope. Secret deletion is operationally significant and can affect live Keycloak clients.

## Secret lifecycle and deletion ownership

The SPI can write and delete secrets it owns, but it does not blindly remove unrelated Vault data. When `managed-secret-prefix` is configured, the SPI keeps its own data under a designated namespace and only deletes that sub-tree during client cleanup.

When `managed-secret-prefix` is unset, the legacy behavior remains for backward compatibility. Operators are expected to understand that the plugin may write and delete only the resolved client-secret path from the configured mount.

## Logging and secret safety

The runtime and tests explicitly avoid logging Vault tokens, Kubernetes JWTs, AppRole credentials, or client secret material. If a failure occurs, logs should describe the operation and HTTP status rather than echoing the secret or token value.

## TLS and transport hardening

- Keep Vault on HTTPS in production.
- Do not disable certificate validation or hostname verification.
- Reuse the Keycloak HTTP client and trust configuration instead of creating ad hoc insecure clients.
- Make any custom truststore configuration explicit and documented.

See [OPERATIONS.md](OPERATIONS.md) for retry and outage behavior.
