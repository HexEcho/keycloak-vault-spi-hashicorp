# Operations and Failure Semantics

## Retry policy

The SPI retries only failures that are considered transient:

- HTTP 429
- HTTP 500
- HTTP 502
- HTTP 503
- HTTP 504
- connection resets
- connect/read timeouts

The project does not retry:

- HTTP 400
- HTTP 401
- HTTP 403
- HTTP 404

The retry loop is bounded by the configured `retry-max-attempts`, `retry-initial-delay-ms`, and `retry-max-delay-ms`. The backoff is exponential with jitter, capped to the configured maximum delay.

## Failure behavior by status

| Condition | Behavior |
|---|---|
| 403 | Authentication or authorization failure. The secret service refreshes the token once and retries once before failing. |
| 404 | Secret or path does not exist. Treated as an expected lookup result for missing secrets. |
| 429 | Rate limiting. Retries are bounded and eventually fail closed. |
| 5xx | Transient server failure. Retries are attempted until the retry limit is exhausted. |
| Timeout | Retries are attempted according to the bound; if the bound is exhausted, the operation fails without indefinite blocking. |
| Authentication failure | Log and return failure; token refresh is attempted once as part of the short-lived reauth loop. |
| Cache hit during outage | A cached value can satisfy the request without contacting Vault. |
| Cache miss during outage | The operation fails unless a fresh Vault request succeeds. |

## Operational guidance

- Keep a Vault HA configuration in front of the backend storage, with a load balancer or active-active pattern.
- Prefer a consistent retry budget that balances availability with not amplifying the outage.
- Use the health check only for diagnostics; it is intentionally not on the critical request path.
- Monitor Vault request failures, request duration, auth failures, cache hits, and cache misses using your runtime monitoring stack.

## Recommended timeouts

- connect-timeout-ms: 2000
- read-timeout-ms: 5000
- request-timeout-ms: 5000

These defaults are conservative and were chosen to keep the request path responsive without causing excessive retry storms.
