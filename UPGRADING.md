# Upgrading and Compatibility Guide

## Supported baseline

The supported baseline for this project is Keycloak 26.7.3. This is the version used in the Maven build and the repository test suite.

## Before upgrading

1. Update the Keycloak dependency version in [pom.xml](pom.xml).
2. Rebuild the project with `mvn test`.
3. Re-run all integration tests that rely on Testcontainers and Vault.
4. Review the compatibility-sensitive APIs listed in [KEYCLOAK_COMPATIBILITY.md](KEYCLOAK_COMPATIBILITY.md).

## Compatibility-sensitive code paths

The following areas are the most likely to require a source-level check after a Keycloak upgrade:

- `HashicorpVaultClient`
- `VaultAwareClientIdAndSecretAuthenticator`
- `HashicorpVaultCaches`
- `HashicorpVaultCacheConfigProviderFactory`
- `HashicorpVaultAdminEventListenerFactory`

## Backward compatibility

This project intentionally preserves the legacy path layout unless `managed-secret-prefix` is configured. That keeps existing installs working while allowing stronger isolation for new deployments.

## Migration pattern

For upgrades that involve a new Keycloak release line:

- recompile with the target version;
- validate the compatibility-sensitive classes;
- confirm the supported runtime policy before publishing a release;
- document any remaining compatibility risk in the release notes.
