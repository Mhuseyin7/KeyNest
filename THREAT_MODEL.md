# Threat model

## Assets and trust boundaries

Secret plaintext exists only at API decrypt time and in the authorized CLI child environment. PostgreSQL holds ciphertext, per-value nonce/version/metadata, and wrapped DEKs. The externally supplied master key is a separate trust boundary. Browser, API, database, CLI, reverse proxy, backups, and CI are distinct boundaries.

| Threat | Primary mitigations | Residual risk |
|---|---|---|
| Stolen database / backup | AES-256-GCM envelopes; DEKs wrapped outside DB; encrypted storage and restricted backup access | Metadata and encrypted material remain sensitive; master-key loss prevents recovery |
| Compromised API server | Least privilege, hardened host, short-lived sessions/tokens, audit trails, rate limits | A live server holding the master key can decrypt authorized values |
| Stolen service token | Random token hash at rest, prefix lookup, scope, expiry, revocation, one-time display | Token works until expiry/revocation; minimize scope |
| XSS / malicious secret input | React escaping, no HTML rendering, CSP, no value interpolation into markup | A compromised trusted origin still harms session users |
| Malicious team member | Explicit permissions, production reauthentication, audit events, least privilege | Authorized readers can exfiltrate values |
| Logs / telemetry | Structured field denylist, no request-body logging, privacy-off default, tests | Third-party host/process logs must be separately controlled |
| Brute force / replay | Argon2id, rate limiting, generic login failures, expiring opaque credentials, TLS | DoS remains possible without upstream protection |
| Tenant escape | Organization IDs on every resource query, membership checks, integration tests | Application bugs require ongoing review |

## Cryptography

KeyNest uses the audited `cryptography` library’s AES-256-GCM implementation. A random 32-byte DEK encrypts one secret version with a fresh 96-bit nonce. The DEK is itself encrypted with the externally supplied 32-byte master key using a separate fresh nonce and authenticated associated data binding the organization and encryption version. Nonces are generated with `secrets.token_bytes`; they are never derived or reused. Key rotation is an explicit migration operation.

## Non-goals

KeyNest is not an endpoint protection system or a personal password manager. It cannot protect a secret after an authorized process receives it, nor recover data if all copies of the master key are permanently lost.

