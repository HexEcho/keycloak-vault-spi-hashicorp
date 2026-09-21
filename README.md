# Keycloak HashiCorp Vault SPI

*Disclaimer: This project is not affiliated with, endorsed by, or supported by Red Hat, Inc., the Keycloak project, or HashiCorp, Inc.*

This JAR is a Keycloak **Vault SPI** provider (`id=hashicorp`) for **Keycloak / Red Hat build of Keycloak 26.4.x**. Keycloak stores `${vault.key}` pointers. Secret values live in HashiCorp Vault KV.

It also:

* Resolves those pointers for **confidential client secrets** at token time (Keycloak 26.4 does not do this by itself; 26.6 does).
* Writes a generated confidential-client secret to Vault on **client create** and **Regenerate secret**, then stores `${vault.{clientId}}` in Keycloak.

Do **not** set `--vault=file` or `--vault=keystore`. Select this provider with `--spi-vault--provider=hashicorp`.

**Runtime target:** Keycloak **26.4.10** (RHBK **26.4.12** is the tested distribution). Compile uses Maven Central **26.4.7** (last community 26.4.x); the Vault SPI matches 26.4.10.

---

## What this SPI does

### Components Keycloak already provides (reused, not replaced)

| Keycloak component | How this SPI uses it |
|---|---|
| Vault SPI (`AbstractVaultProvider` / `AbstractVaultProviderFactory`) | `${vault.key}` lookup, key resolvers |
| `SimpleHttp` / `HttpClientProvider` | All outbound HTTP to Vault (no private HTTP client) |
| Infinispan embedded cache manager | LOCAL cache `hashicorp-vault` for KV values |
| `client-secret` authenticator | Replaced with a higher-`order()` factory of the same id so token requests resolve `${vault.key}` |
| Admin events | Global listener `hashicorp-vault` writes generated client secrets and invalidates cache |

The JAR does **not** bundle Keycloak, Infinispan, or a HashiCorp SDK. Those APIs are `provided` at compile time and come from the Keycloak server at runtime.

### Lookup (read)

Admin fields store a pointer, not the secret:

```text
${vault.xyz}
```

Keycloak resolvers turn that into a Vault path. With `key-resolvers=REALM_FILESEPARATOR_KEY` (recommended for realm folders):

| Realm | Expression | KV v2 path | Field |
|---|---|---|---|
| `demo` | `${vault.xyz}` | `{url}/v1/secret/data/demo/xyz` | `value` (default) |

Default resolver `REALM_UNDERSCORE_KEY` would use `secret/data/demo_xyz` instead.

Request shape:

```text
GET {url}/v1/{kv-mount}/data/{resolvedKey}     # kv-version=2
GET {url}/v1/{kv-mount}/{resolvedKey}        # kv-version=1
Header: X-Vault-Token
Header: X-Vault-Namespace                     # only if namespace is set
Read:   data.data.{kv-field}                  # KV v2; default field "value"
```

LDAP bind credential, SMTP password, and identity-provider client secret are **read-only**: put the secret in Vault first, then set the Keycloak field to `${vault.key}`.

### Confidential clients (read + write)

1. Create a confidential client (Client authentication ON), or click **Regenerate secret**.
2. Keycloak generates a secret.
3. This SPI `PUT`s `{kv-mount}/data/{realm}/{clientId}` (with `REALM_FILESEPARATOR_KEY`) field `value`.
4. Keycloak stores `${vault.{clientId}}`.
5. Token requests send the **real** secret. The vault-aware `client-secret` authenticator resolves the pointer and compares.

When the client is deleted, this SPI deletes the corresponding managed Vault entry as well. KV v2 deletion removes all versions through the metadata endpoint. A missing entry is treated as already deleted; manually managed Vault entries are not touched.

If the Vault write fails, the generated secret stays in Keycloak.

The Admin Console Credentials tab still shows the newly generated secret **once** (POST response). Leave the client and open it again: the stored value should be `${vault.xyz}`.

---

# 1. Building this SPI

## Build-time dependencies

**Machine**

* JDK **17**
* Apache Maven **3.8+** (3.9 is fine)

**Maven compile dependencies** (`provided` — not packaged into the JAR)

| Artifact | Version | Why |
|---|---|---|
| `org.keycloak:keycloak-server-spi` | 26.4.7 | Vault SPI, `ClientModel`, `Config.Scope` |
| `org.keycloak:keycloak-server-spi-private` | 26.4.7 | `SimpleHttp`, admin events, private SPI |
| `org.keycloak:keycloak-services` | 26.4.7 | `AbstractVaultProvider*`, `ClientIdAndSecretAuthenticator` |
| `org.keycloak:keycloak-model-infinispan` | 26.4.7 | `InfinispanConnectionProvider`, cache config SPI |
| `org.jboss.logging:jboss-logging` | 3.5.0.Final | Logging |

**Test only:** `org.junit.jupiter:junit-jupiter` 5.10.2

There is **no** HashiCorp Java SDK, extra HTTP client, or extra JSON library. JSON uses Keycloak `JsonSerialization`.

## Build

```bash
mvn clean package
```

Artifact:

```text
target/keycloak-vault-integration-hashicorp-1.0.0.jar
```

Run tests without packaging:

```bash
mvn test
```

---

# 2. Deploying and configuring this SPI

## Runtime dependencies

Install these **before** this JAR can work:

| Component | Role | Notes |
|---|---|---|
| Keycloak **26.4.10** or RHBK **26.4.x** (tested **26.4.12**) | Host for the JAR | Java 17. Copy the JAR into **this** install’s `providers/`, not an older 26.0.x tree. |
| HashiCorp Vault (OSS or Enterprise) | Secret store | KV secrets engine v1 or v2 (v2 is the default in this SPI) |
| Network path Keycloak → Vault | HTTP(S) | Vault URL must be reachable from the Keycloak process |
| Vault auth credentials | Token, AppRole, or TLS cert | See [Authentication with HashiCorp](#authentication-with-hashicorp) |
| Vault Enterprise namespace | Optional isolation | Set SPI `namespace` if the cluster uses namespaces |

Do not run this JAR on Keycloak **26.0.x**. It uses `org.keycloak.http.simple.SimpleHttp` (26.4).

Do not point this JAR at a database that a **newer** Keycloak already migrated if you are still starting an older Keycloak.

## HashiCorp: what to do before integration

Do this on Vault **before** (or as the first step of) wiring Keycloak.

### 1. KV engine

This SPI defaults to mount `secret`, version **2**, field `value`.

```bash
# if KV v2 is not already at secret/
vault secrets enable -path=secret kv-v2
```

If you use another mount or KV v1, set `kv-mount` / `kv-version` on Keycloak to match.

### 2. Path layout (must match Keycloak resolvers)

With `--spi-vault--hashicorp--key-resolvers=REALM_FILESEPARATOR_KEY`:

```text
secret/data/{realm-name}/{vault-key}
```

Examples:

```bash
# LDAP bind in realm master, expression ${vault.ldapBc}
vault kv put secret/master/ldapBc value='bind-password'

# Confidential client xyz in realm demo, expression ${vault.xyz}
vault kv put secret/demo/xyz value='the-client-secret'
```

The field name must be the configured `kv-field` (default `value`). A field named after the client id (`abc=secret`) will **not** be read unless you set `kv-field=abc` (that field is then used for **every** secret).

LDAP / SMTP / IdP: create the KV entry **before** putting `${vault.key}` in Keycloak.

Confidential clients: this SPI can `PUT` the path for you on create/regenerate. The policy must still allow write.

### 3. Policy (least privilege, read and write for client secrets)

Prefer a **realm-scoped** policy over a wildcard across every realm. With `key-resolvers=REALM_FILESEPARATOR_KEY` each realm's secrets live under `secret/data/<realm>/...`, so a policy can be written per realm (or per tenant):

```hcl
# Read-only lookup, one realm only
path "secret/data/<realm>/*" {
  capabilities = ["read"]
}
```

For client create / regenerate (this SPI writes KV) in that same realm only:

```hcl
path "secret/data/<realm>/*" {
  capabilities = ["create", "update", "read"]
}

# optional, so operators can list that realm's folder
path "secret/metadata/<realm>/*" {
  capabilities = ["list"]
}
```

If `managed-secret-prefix` is set (see [Managed vs externally managed secrets](#managed-vs-externally-managed-secrets)), scope the write capability further to just that sub-path so this SPI can never write or delete outside its own namespace:

```hcl
path "secret/data/<realm>/<managed-secret-prefix>/*" {
  capabilities = ["create", "update", "read"]
}
path "secret/metadata/<realm>/<managed-secret-prefix>/*" {
  capabilities = ["read", "delete"]
}
```

Only fall back to a mount-wide policy (`path "secret/data/*" { capabilities = ["read"] }`) when a single Vault token must legitimately serve every realm (for example a shared AppRole used by all of a multi-realm Keycloak's realms) — this is a deliberate, documented trade-off, not the default recommendation. Substitute your own `kv-mount` if it is not `secret`. On Enterprise, create the policy **inside the namespace** Keycloak will use.

### 4. Authentication method on Vault

Enable **one** of token, AppRole, Kubernetes, or cert. Details are under [Authentication with HashiCorp](#authentication-with-hashicorp).

### 5. Namespace (Enterprise only)

If the customer isolates tenants with namespaces, create the namespace, enable KV and auth **in that namespace**, and put the same name in SPI `namespace` (for example `admin/team-a`). Nested namespaces use `parent/child`. Open-source Vault and the root namespace: leave `namespace` unset.

## Install the JAR on Keycloak

```bash
cp target/keycloak-vault-integration-hashicorp-1.0.0.jar "$KEYCLOAK_HOME/providers/"
"$KEYCLOAK_HOME/bin/kc.sh" build
```

Restart Keycloak after `build`. Copying the JAR without `kc.sh build` (except `start-dev`, which rebuilds) will not load the provider.

## Configuration rules

Keycloak maps SPI options itself. Do not invent extra environment variables.

| Source | Example |
|---|---|
| CLI (Keycloak **26.1+** / 26.4) | `--spi-vault--hashicorp--token=...` |
| Environment | `KC_SPI_VAULT__HASHICORP__TOKEN` |
| `conf/keycloak.conf` | `spi-vault--hashicorp--token=...` |

Keycloak **26.0** used single dashes (`--spi-vault-hashicorp-token`). This product targets **26.4** double dashes.

Always set the provider (mandatory):

```bash
--spi-vault--provider=hashicorp
```

## SPI options: mandatory vs optional

### Always required to use this product

| Option | CLI | Why |
|---|---|---|
| Vault provider id | `--spi-vault--provider=hashicorp` | Without this, Keycloak will not use this JAR as the vault |

### Required in practice (have defaults, must be correct for your site)

| Property | CLI | Default | Required? |
|---|---|---|---|
| `url` | `--spi-vault--hashicorp--url` | `http://127.0.0.1:8200` | **Required in production.** Default is only for local Vault. |
| `auth-method` | `--spi-vault--hashicorp--auth-method` | `token` | **Required to choose.** Values: `token`, `approle`, `kubernetes`, `cert` (aliases: `certificate`, `tls`, `tls-cert`). |

### Required depending on `auth-method`

| `auth-method` | Mandatory | Optional |
|---|---|---|
| `token` | `--spi-vault--hashicorp--token` | — |
| `approle` | `--spi-vault--hashicorp--approle-role-id` **and** `--spi-vault--hashicorp--approle-secret-id` | `--spi-vault--hashicorp--approle-mount-path` (default `approle`) |
| `kubernetes` | `--spi-vault--hashicorp--kubernetes-role` | `--spi-vault--hashicorp--kubernetes-mount-path` (default `kubernetes`), `--spi-vault--hashicorp--kubernetes-jwt-path` (default `/var/run/secrets/kubernetes.io/serviceaccount/token`) |
| `cert` | Keycloak outbound client keystore (see cert section). Vault must have `auth/cert` enabled and trust that certificate. | `--spi-vault--hashicorp--cert-name` (Vault cert role name), `--spi-vault--hashicorp--cert-mount-path` (default `cert`) |

If `auth-method=token` and `token` is empty, lookups fail (`Vault token is not configured`). If AppRole or Kubernetes configuration is missing, login fails explicitly (no fallback to another method, and **no static Vault token is required** for `approle` or `kubernetes`).

### Optional (safe defaults)

| Property | CLI | Default | When to set |
|---|---|---|---|
| `namespace` | `--spi-vault--hashicorp--namespace` | unset | **Required** on Vault Enterprise with namespaces. Omit for OSS / root. |
| `kv-mount` | `--spi-vault--hashicorp--kv-mount` | `secret` | If KV is not mounted at `secret` |
| `kv-version` | `--spi-vault--hashicorp--kv-version` | `2` | `1` only if the mount is KV v1 |
| `kv-field` | `--spi-vault--hashicorp--kv-field` | `value` | If secrets are not stored in field `value` |
| `key-resolvers` | `--spi-vault--hashicorp--key-resolvers` | `REALM_UNDERSCORE_KEY` | Set `REALM_FILESEPARATOR_KEY` for `{realm}/{key}` folders |
| `cache-ttl` | `--spi-vault--hashicorp--cache-ttl` | `300000` (ms) | `0` disables Infinispan caching |
| `managed-secret-prefix` | `--spi-vault--hashicorp--managed-secret-prefix` | unset | Set (for example `managed`) to isolate SPI-written confidential-client secrets under `<realm>/<prefix>/<clientId>`, see [Managed vs externally managed secrets](#managed-vs-externally-managed-secrets). Unset preserves the existing path. |

### Other Keycloak SPI used by this product (not this JAR’s properties)

| Purpose | Option | Required? |
|---|---|---|
| Outbound HTTPS to Vault (trust server cert) | Keycloak truststore, e.g. `https-trust-store-file` / `spi-truststore--file--file` | When Vault URL is `https://` with a private CA |
| Outbound mTLS for **cert** auth | `--spi-connections-http-client--default--client-keystore` and `--spi-connections-http-client--default--client-keystore-password` | **Mandatory for `auth-method=cert`** |
| Optional key password | `--spi-connections-http-client--default--client-key-password` | If the private key password differs |

That HTTP client keystore is **process-wide** (all Keycloak outbound HTTPS).

Do **not** set `--vault=file` or `--vault=keystore`. Those select a different vault provider.

## Authentication with HashiCorp

Outbound HTTP always uses Keycloak `SimpleHttp`. After login, every KV call sends `X-Vault-Token`. If `namespace` is set, every call (including login) also sends `X-Vault-Namespace`.

AppRole and cert tokens are cached until 90% of `lease_duration`. HTTP 403 invalidates the cached token and retries login once. A static token is not renewed; rotate it in config and restart.

### A. Token (static)

**Vault**

```bash
vault policy write keycloak keycloak-policy.hcl
vault token create -policy=keycloak -ttl=768h
```

**Keycloak (mandatory: `provider`, `url` in production, `auth-method`, `token`)**

```bash
bin/kc.sh start \
  --spi-vault--provider=hashicorp \
  --spi-vault--hashicorp--url=https://vault.example.com:8200 \
  --spi-vault--hashicorp--auth-method=token \
  --spi-vault--hashicorp--token="$VAULT_TOKEN"
```

Optional: `--spi-vault--hashicorp--namespace=admin/team-a`

### B. AppRole

**Vault**

```bash
vault auth enable approle
vault write auth/approle/role/keycloak \
  token_policies=keycloak \
  token_ttl=1h \
  token_max_ttl=4h

vault read -field=role_id auth/approle/role/keycloak/role-id
vault write -field=secret_id -f auth/approle/role/keycloak/secret-id
```

If AppRole is enabled at another path, set `approle-mount-path`.

**Keycloak (mandatory: `approle-role-id`, `approle-secret-id`)**

```bash
bin/kc.sh start \
  --spi-vault--provider=hashicorp \
  --spi-vault--hashicorp--url=https://vault.example.com:8200 \
  --spi-vault--hashicorp--auth-method=approle \
  --spi-vault--hashicorp--approle-role-id="$ROLE_ID" \
  --spi-vault--hashicorp--approle-secret-id="$SECRET_ID"
```

Optional: `--spi-vault--hashicorp--approle-mount-path=approle`, `--spi-vault--hashicorp--namespace=...`

Login used by this SPI: `POST {url}/v1/auth/{mount}/login` with `role_id` and `secret_id`.

### C. Kubernetes

Vault authenticates the pod's projected service-account JWT against the Kubernetes API. This SPI reads the JWT from disk **fresh for every login attempt**; it is never cached in memory beyond that single call, never persisted, and never logged.

**Vault**

```bash
vault auth enable kubernetes
vault write auth/kubernetes/config \
  kubernetes_host="https://$KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT"

vault write auth/kubernetes/role/keycloak \
  bound_service_account_names=keycloak \
  bound_service_account_namespaces=keycloak \
  policies=keycloak \
  ttl=1h
```

**Keycloak (mandatory: `kubernetes-role`; optional: `kubernetes-mount-path`, `kubernetes-jwt-path`)**

```bash
bin/kc.sh start \
  --spi-vault--provider=hashicorp \
  --spi-vault--hashicorp--url=https://vault.example.com:8200 \
  --spi-vault--hashicorp--auth-method=kubernetes \
  --spi-vault--hashicorp--kubernetes-role=keycloak \
  --spi-vault--hashicorp--kubernetes-mount-path=kubernetes \
  --spi-vault--hashicorp--kubernetes-jwt-path=/var/run/secrets/kubernetes.io/serviceaccount/token
```

Login used by this SPI: `POST {url}/v1/auth/{kubernetes-mount-path}/login` with body `{"role": "<kubernetes-role>", "jwt": "<service-account-jwt>"}`. No `--spi-vault--hashicorp--token` is required or read when `auth-method=kubernetes`. A missing/empty/unreadable JWT file, a missing role, or a Vault-side rejection all fail the login explicitly (return no token) instead of retrying indefinitely; the calling vault lookup then fails closed rather than falling back to another auth method.

### D. TLS / certificate

Vault cert auth is **mTLS**, not a PEM pasted into this SPI. Keycloak’s outbound HTTP client presents the client certificate. This SPI then `POST`s `{url}/v1/auth/{cert-mount}/login` (optional JSON `{"name":"<cert-name>"}`) and caches `auth.client_token`.

**Vault**

```bash
vault auth enable cert
vault write auth/cert/certs/keycloak \
  display_name=keycloak \
  policies=keycloak \
  certificate=@keycloak-client.crt \
  ttl=1h
```

The certificate in that command must match the one in Keycloak’s `client-keystore`.

**Keycloak (mandatory: HTTP client keystore; optional: `cert-name`, `cert-mount-path`)**

```bash
bin/kc.sh start \
  --spi-connections-http-client--default--client-keystore=/path/to/vault-client.p12 \
  --spi-connections-http-client--default--client-keystore-password="$KEYSTORE_PASSWORD" \
  --spi-vault--provider=hashicorp \
  --spi-vault--hashicorp--url=https://vault.example.com:8200 \
  --spi-vault--hashicorp--auth-method=cert \
  --spi-vault--hashicorp--cert-name=keycloak
```

`auth-method` may be `cert`, `certificate`, `tls`, or `tls-cert`. Trust Vault’s server certificate with Keycloak’s truststore.

## Managed vs externally managed secrets

Secrets in Vault fall into two categories:

* **Managed** — confidential-client secrets this SPI itself writes on client create/regenerate and removes on client delete.
* **Externally managed** — anything an operator puts in Vault directly (LDAP bind password, SMTP password, IdP client secret, or a confidential-client secret an operator chose to manage by hand).

By default (`managed-secret-prefix` unset) managed secrets share the same `<realm>/<clientId>` path as before, for backward compatibility. Setting `--spi-vault--hashicorp--managed-secret-prefix=managed` moves every managed secret this SPI writes or deletes to an explicit, separate namespace:

```text
secret/data/<realm>/managed/<clientId>
```

This SPI never deletes a Vault entry unless: (1) the corresponding Keycloak client's stored secret is still the exact `${vault.<clientId>}` pointer this SPI wrote, and (2) the resolved path passes `VaultPathResolver` validation. An operator-managed secret at any other path, or a path an admin has since repointed by hand, is left untouched. Migrating an existing deployment to `managed-secret-prefix` does not move already-written secrets — write (or let a secret regenerate) once after changing the setting so the new path is populated, and manually remove the old-path entry if it is no longer needed.

## Full start examples

**26.4 `start` with token + realm folders + namespace**

```bash
bin/kc.sh start \
  --spi-vault--provider=hashicorp \
  --spi-vault--hashicorp--url=https://vault.example.com:8200 \
  --spi-vault--hashicorp--namespace=admin/team-a \
  --spi-vault--hashicorp--auth-method=token \
  --spi-vault--hashicorp--token="$VAULT_TOKEN" \
  --spi-vault--hashicorp--key-resolvers=REALM_FILESEPARATOR_KEY
```

**Local `start-dev` (same flags, one line)**

```bash
bin/kc.sh start-dev --spi-vault--provider=hashicorp --spi-vault--hashicorp--url=http://127.0.0.1:8200 --spi-vault--hashicorp--auth-method=token --spi-vault--hashicorp--token="$VAULT_TOKEN" --spi-vault--hashicorp--key-resolvers=REALM_FILESEPARATOR_KEY
```

Put every flag on **one** command. A newline without `\` starts a second shell command; `token` will not reach Java.

Same values in `conf/keycloak.conf`:

```properties
spi-vault--provider=hashicorp
spi-vault--hashicorp--url=https://vault.example.com:8200
spi-vault--hashicorp--auth-method=token
spi-vault--hashicorp--token=${VAULT_TOKEN}
spi-vault--hashicorp--key-resolvers=REALM_FILESEPARATOR_KEY
```

## Sample test scenario (curl)

Assumes: Vault at `http://127.0.0.1:8200`, Keycloak at `http://localhost:8080`, realm `demo`, confidential client `xyz`, user `hexecho` with password `secret`, Direct access grants enabled, resolver `REALM_FILESEPARATOR_KEY`, KV field `value`.

### 1. Vault

```bash
export VAULT_ADDR=http://127.0.0.1:8200
vault kv put secret/demo/xyz value='secret'
vault kv get secret/demo/xyz
```

### 2. Keycloak client pointer (if you did not rely on auto-write)

```bash
# replace the UUID with the client’s id from the Admin Console or kcadm
./kcadm.sh config credentials --server http://localhost:8080 --realm master --user admin
./kcadm.sh update clients/<CLIENT_UUID> -r demo -s 'secret=${vault.xyz}'
```

Do not click **Regenerate secret** if you only want to keep a hand-written pointer; regenerate **overwrites** Vault with a new value and then stores `${vault.xyz}` again.

### 3. Token request (send the real secret, not the pointer)

```bash
curl -s http://localhost:8080/realms/demo/protocol/openid-connect/token \
  -d grant_type=password \
  -d client_id=xyz \
  -d client_secret=secret \
  -d username=hexecho \
  -d password=secret
```

A successful body contains `access_token`. Failure `unauthorized_client` / `invalid_client_credentials` means the presented secret did not match Vault `value` (or the pointer was not resolved).

### 4. Auto-write on create

Create a confidential client `cdf` in realm `demo` with Client authentication ON. Then:

```bash
vault kv get secret/demo/cdf
```

You should see field `value`. In Keycloak, after leaving and reopening the client, the secret field should be `${vault.cdf}`.

Repeat the curl from step 3 with `client_id=cdf` and `client_secret` equal to that Vault `value`.

### 5. LDAP / SMTP / IdP (read-only)

```bash
vault kv put secret/demo/ldapBc value='bind-password'
```

Set the LDAP bind credential to `${vault.ldapBc}`. There is no write-back for LDAP/SMTP/IdP.

## After deploy: Keycloak realm settings

* Copy the JAR, `kc.sh build`, restart with `--spi-vault--provider=hashicorp` and a complete auth set.
* Boot log should show `HashiCorp vault provider initialized` and **must not** say `Vault token is not configured` when using `auth-method=token`.
* Listener id `hashicorp-vault` is **global** (regenerate works without adding it under Realm Settings → Events). You may still add it there if you want it listed.
* Direct access grants must be on for the password-grant curl sample.
* Do not use **Regenerate secret** expecting the old Vault value to remain; regenerate writes a new secret to Vault.

## License

Apache License 2.0.
