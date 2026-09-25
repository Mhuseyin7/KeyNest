# Security policy

Report vulnerabilities privately to the maintainers; do not open public issues with exploit details. Include affected version, reproduction steps, and impact. Acknowledgements will be coordinated before disclosure.

## Deployment requirements

- Terminate TLS at a trusted proxy and set `KEYNEST_PUBLIC_ORIGIN` to its HTTPS origin.
- Provide `KEYNEST_MASTER_KEY` via a protected process environment, Docker/Kubernetes secret, or future KMS adapter. It must be 32 random bytes encoded with URL-safe base64 and must not be in PostgreSQL, source control, image layers, or logs.
- Use a managed PostgreSQL instance with encrypted storage, restricted network access, backups, and unique credentials.
- Set a high-entropy session secret and configure secure, HttpOnly, SameSite cookies.
- Cookie-authenticated state changes require a CSRF header matching the short-lived `keynest_csrf` cookie; API clients should use short-lived Bearer credentials instead.
- Do not enable credentialed CORS for untrusted origins. The API defaults to a single configured origin.

## Environment-variable limitations

KeyNest does not write `.env` files during `run`. It cannot make a child process’s environment universally invisible: users with sufficient OS privileges, debuggers, crash dump tools, process-inspection facilities, and some service managers may access it. Run workloads under separate least-privilege accounts, disable core dumps where appropriate, and avoid logging complete environments.

## Logging and telemetry

Secret-aware logging rejects known secret-bearing fields. Never add values, request bodies for reveal/set routes, Authorization headers, or environment maps to logs. Telemetry is disabled by default and must never transmit secret values, secret names, project names, or environment names.
