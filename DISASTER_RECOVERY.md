# Disaster recovery

Backups contain sensitive encrypted secret material and metadata. Restrict them as carefully as production data, encrypt them, test restores, and retain audit history according to policy.

## Master key recovery

Store the master key in a dedicated secret system or split offline escrow process independent of PostgreSQL. Document key identifiers, custodians, rotation dates, and the recovery procedure. Restore the database **and the matching master key** to an isolated environment, validate decryption of a controlled sample, then rotate credentials and investigate the incident.

If the master key is permanently lost, encrypted secrets cannot be recovered. Do not attempt to bypass this property or replace the key in place; provision a new key and re-enter/rotate affected values.

## Incident actions

1. Restrict access and preserve logs without including secret values.
2. Revoke service tokens and sessions, then rotate affected external credentials.
3. Restore only after identifying the compromise boundary.
4. Review audit events, memberships, token creation, reveals, and exports.

