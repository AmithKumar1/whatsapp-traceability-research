# Architecture and Module Boundaries

## Top-level packages

### 1. `protocols/`

Implements prospective, protocol-specific cryptographic tracing. Each adapter carries a research status (unreviewed, replicated, reviewed, production-considered), paper version, security profile, code commit, supported modes, and known deviations. Research adapters must not share assumptions implicitly.

Planned adapter folders:

```text
protocols/
  synthetic_graph/       # current graph demonstrator; no cryptographic claim
  traceback_2019/        # separate path and tree submodules
  source_tracking_2021/
  hts_2025/
  minimal_trust_2026/
```

### 2. `policy/`

- `Authorization`: typed and signed request structure.
- `Scope`: target, content commitment, mode, purpose, time validity, excluded data.
- `QuorumPolicy`: distinct participants, allowed key types, threshold, failure policy.
- `PolicyEngine`: validates structure, cryptographic signatures, freshness, replay, signer/revocation status, and requested mode.
- `JurisdictionProfile`: versioned rule parameters reviewed by lawyers; does not make a generic legal determination.

### 3. `identity/`

Maps protocol credentials, account IDs, devices, provider-signed phone bindings, and person-level evidence. All mappings are versioned over time. Avoid global plaintext-phone-number indexes by default. An identity-resolution service cannot widen the authorization scope.

### 4. `evidence/`

- `acquisition_manifest`: describes original files and acquisition metadata.
- `importers`: parser per artifact type/version with explicit coverage and limitations.
- `provenance_graph`: input records, derived records, transformations, hashes, and evidence links.
- `validation`: schema, hash, signature, certificate, timestamp, and parser checks.
- `redaction`: generated views preserving source-to-derivative links.

Initial adapters should be non-invasive: WhatsApp Traceability Research Lab JSON events and investigator-supplied files. Real WhatsApp-specific parsers remain future work and require separate versioned research.

### 5. `casefile/`

Builds a portable signed bundle: signed canonical manifest, hash chain, evidence references, trace output, authorization, audit events, and optional timestamp/transparency proofs. The bundle can be copied to another machine for independent verification.

### 6. `audit/`

Append-only case action events. Each event should bind prior hash, actor credential, action type, scope, policy version, case ID, result, event-time source, and signature. A local chain is useful but not equivalent to an independent transparency log.

### 7. `bench/` and `redteam/`

Reproducible parameter sweeps, protocol overhead calculations, malicious-server simulation, threshold/collusion testing, and scenario corpora. Every run captures versions, seed, hardware profile, configuration, and raw results.

### 8. UI / CLI

The UI must avoid sensational “guilty” language. It shows evidence provenance, verified status, unknowns, and scope. The CLI should be deterministic and usable offline. Do not send evidence to a hosted model or analytics service by default.

## Data flow

1. Receive the reported message reference/complaint and validated authorization object.
2. Confirm the content commitment corresponds to the complaint object under the adapter's definition.
3. Evaluate policy scope, expiry, signatures, quorum and replay protection.
4. Ask only the selected protocol adapter for permitted output.
5. Verify the returned proof bundle locally.
6. Resolve identity only where separately allowed and supported by provider/evidence assertion.
7. Filter output to approved disclosure mode.
8. Produce a signed case bundle and audit event.
9. An independent verifier checks signatures, evidence hashes, timestamp proofs and transparency proofs.
10. Return trace status, confidence/assurance labels, missing coverage and limitations.

## Failure behavior

- Any invalid signature, malformed proof, unknown algorithm/version, scope mismatch, expired authorization or missing required quorum: stop and return a typed denial/error.
- Missing event/record or partial protocol state: return partial/unknown, not a guessed origin.
- If the event graph has a cycle or multiple origins inconsistent with adapter semantics: reject the graph.
- If two timestamp intervals overlap or clocks conflict: show ambiguity.
- If content transformation breaks a cryptographic reference: do not use text similarity to silently bridge it; a candidate similarity may be recorded separately.
