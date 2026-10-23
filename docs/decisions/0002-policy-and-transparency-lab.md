# ADR 0002: Add a policy-verification layer and local Merkle proof lab

- **Status:** Accepted for v0.2 as experimental components
- **Date:** 2026-10-23

## Context

The v0.1 scaffold detected payload changes under a signed manifest but did not enforce a complete file inventory or demonstrate multi-party approvals. Evidence records could be hashed locally, but a hash chain alone is not independently witnessed transparency. Research on encrypted-message traceability also makes abuse resistance and minimal disclosure core design concerns, not optional UI features.

## Decision

1. Add strict JSON parsing that rejects duplicate keys and non-standard numeric constants.
2. Move the evidence manifest format to v0.2 with recorded file sizes, signer public-key fingerprint, record-count checking, reserved control-file names, safe canonical relative paths, symlink rejection, and full payload-inventory comparison.
3. Add request-bound Ed25519 approvals. Each approval signs the request digest, approver identity reference, role, trust domain, decision, and timestamp. A configurable policy can require minimum approvals, distinct approvers/domains, roles, expiry, and allowed disclosure modes.
4. Add an offline Merkle inclusion-proof lab using RFC 9162-style domain separation and a reproducible microbenchmark.
5. Keep protocol tracing engines separate. These additions do not implement any of the published E2EE traceback/source-tracking constructions.

## Consequences

- Local integrity checks are materially stronger and have more adversarial tests.
- Multi-party approvals are only as sound as the separately governed trust registry, protected signing keys, and policy. The code does not validate legal orders or guarantee organizational independence.
- Merkle proofs are only inclusion proofs against the locally computed root. Without a signed tree head, independent monitors, and consistency proof across snapshots, they do not provide an operational transparency log.
- Canonical JSON remains a deliberately restricted profile (no floating point), not a complete RFC 8785 implementation. Full JCS is a release gate for interoperable protocol adapters.
- Real evidence workflows remain out of scope until acquisition, retention, authorization, privacy, and external review are independently designed.
