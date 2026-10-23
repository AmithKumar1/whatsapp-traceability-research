# Data Model and Evidence Semantics

## Identifiers

Identifiers are scoped and typed. Avoid reusing an account number, phone number, hash, or file path as multiple concepts.

- `case_id`: case-local identifier, not a global person identifier.
- `event_id`: unique identifier within one case/protocol instance.
- `content_ref`: opaque commitment/object reference defined by the adapter; not a readable text string in production.
- `account_id`: protocol/account credential reference.
- `device_id`: device credential reference.
- `phone_binding_id`: versioned assertion linking a number to an account over an interval.
- `evidence_id`: case-local identifier for an original or derived evidence item.
- `authorization_id`: identifier of the signed request/order record.
- `credential_id`: key/certificate identifier with lifecycle status.

## Event schema concept

```json
{
  "event_id": "evt-123",
  "event_type": "ORIGIN | FORWARD | DELIVER | REPORT",
  "actor_id": "credential-or-pseudonym-reference",
  "timestamp": "2026-10-23T08:30:00Z",
  "time_source": "device | provider | trusted_timestamp | investigator | synthetic",
  "parent_event_id": null,
  "content_ref": "opaque-protocol-reference",
  "evidence_ids": ["evidence-001"],
  "proof_ref": "proof-bundle-reference",
  "credential_id": "key-epoch-ref",
  "sequence": "optional protocol sequence as a string",
  "uncertainty_ms": 0,
  "claim_status": "observed | integrity_verified | protocol_verified | inferred | unknown | synthetic"
}
```

The current v0.2 `trace-event.schema.json` is intentionally smaller than this long-term shape. The schema must evolve under explicit versioning and migration tests.

## Forensic evidence record

Every record needs (where known):

- original filename/path within the case, type and size;
- SHA-256 of original bytes before parsing;
- evidence custodian/source device reference;
- acquisition date/time and time source;
- collection tool/version and procedure;
- operator/authority reference;
- authorization/case reference;
- original vs derived designation;
- transformations/parser version and output hash;
- parent evidence IDs for derived content;
- integrity and signature verification outcomes;
- error/unsupported-version status;
- access/redaction/retention events.

No field should be fabricated when it is not known. Use `unknown` plus an explanatory reason rather than zero or guessed values.

## Evidence graph

Nodes can be messages, artifacts, accounts, devices, keys, people, timestamps, complaints, orders, or claims. Edges are typed: `copied_from`, `forwarded_as`, `contained_in`, `exported_from`, `signed_by`, `bound_to`, `derived_from`, `observed_at`, `authorized_by`, `revoked_by`, `supports`, `contradicts`.

Each edge has its own source references, method, version, and strength. For example, an exact source hash match proves byte identity of two files, not that one sender forwarded the other. A protocol proof can establish a message relation only as defined by that protocol. Similarity analysis creates a candidate relation, not a cryptographic one.

## Assurance ladder

1. **File-integrity assurance:** bytes match a digest in a signed/anchored manifest.
2. **Artifact authenticity assurance:** a valid issuer signature or acquisition/custody record supports the artifact's provenance under stated assumptions.
3. **Protocol assurance:** trace proof validates for a named adapter/version and public keys.
4. **Account-binding assurance:** independently verified record ties a credential to account/number at an interval.
5. **Human identity assurance:** separate identity evidence connects an account/person; never derived automatically from phone number alone.
6. **Activity/intent inference:** whether a named individual actually typed/forwarded the message or intended its content generally requires facts outside the tracing protocol.

Reports must not skip from level 1 to level 5 or 6.
