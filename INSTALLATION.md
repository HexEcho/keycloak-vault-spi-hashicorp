# Installation

This project targets Keycloak 26.7.3 as the supported baseline. The JAR is built with Maven against Keycloak artifacts from the same version and should be deployed into a matching Keycloak installation.

## Prerequisites

- Java 17
- Apache Maven 3.8+
- Keycloak 26.7.3 or a supported RHBK build at the same release line
- Network reachability from Keycloak to HashiCorp Vault
- A Vault token, AppRole, Kubernetes auth role, or TLS certificate identity configured for the Keycloak runtime

## Build

```bash
mvn clean package
```

The artifact is built to:

```text
target/keycloak-vault-integration-hashicorp-1.0.0.jar
```

## Install into Keycloak

```bash
cp target/keycloak-vault-integration-hashicorp-1.0.0.jar "$KEYCLOAK_HOME/providers/"
"$KEYCLOAK_HOME/bin/kc.sh" build
```

Then restart Keycloak.

## Verify provider is loaded

```bash
"$KEYCLOAK_HOME/bin/kc.sh" show-config --all | grep -i vault
```

Or check the provider ID from the server logs:

```text
spi-vault--provider=hashicorp
```

## Configuration notes

- Keep `auth-method` aligned with the accepted Vault identity for the runtime.
- Do not use static tokens in production unless there is a controlled, short-lived operational requirement.
- Prefer workload identity (Kubernetes or certificate auth) over long-lived static secrets.
- If you use a custom Vault namespace, set `namespace` on the provider as well.

See [CONFIGURATION.md](CONFIGURATION.md) for the complete property reference.
