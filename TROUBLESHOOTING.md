# Troubleshooting

## NoClassDefFoundError for `SimpleHttp`

This error means the JAR is running on an incompatible Keycloak version. The project targets Keycloak 26.7.3, not 26.0.x or older. Use the matching Keycloak release line.

## Vault auth fails with 403

- Check the configured auth method and credentials.
- Confirm the Vault token, AppRole role ID/secret ID, or Kubernetes role are valid.
- Review the Vault policy for the target path and namespace.
- Verify the namespace is configured correctly when using Vault Enterprise.

## Secret not found in Vault

- Ensure the `kv-mount` and `kv-version` match the Vault engine configuration.
- Check the resolved path and `kv-field`.
- Confirm the target realm is the same realm used by the client or Keycloak configuration.

## Cache appears stale

- Re-read the secret after a rotation event.
- Ensure the TTL is consistent with the operational requirements.
- If safety requires it, set `cache-enabled=false` for the runtime.

## Client deletion does not remove Vault secret

- Ensure `managed-secret-prefix` is configured if you rely on the managed namespace.
- Confirm the client was actually deleted and the plugin is still installed on the same Keycloak realm.
- Review the Vault policy for delete permissions on the managed path.

## Vault unavailable during startup or at runtime

- The provider will fail the lookup when no successful Vault call is possible.
- Cache hits may continue to work for the remaining TTL, but cache misses cannot be satisfied until Vault is available again.
