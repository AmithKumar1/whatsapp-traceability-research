# Test Plan and Red-Team Matrix

The v0.1/v0.2 counts below are historical. At v0.5.2, the current suite and hosted CI matrix are tracked separately in the changelog and publishing checklist; the CI workflow is the authoritative test run for each commit. The historical baseline has been expanded by tests for approval-policy substitution, public-key path confinement, strict trust registries, schema validation, and offline Merkle input limits.

## 1. Original v0.1 baseline tests

- Graph accepts a well-formed chain and a branch.
- Graph rejects duplicate event IDs.
- Graph rejects an unknown parent.
- Graph rejects a cycle.
- Graph rejects an origin with a parent and non-origin event without a parent.
- Graph rejects content reference mismatch between child and parent.
- Graph rejects zero or multiple origin events for the same `content_ref`.
- Graph rejects missing time zone or malformed timestamp.
- Demo bundle verifies without changes.
- Mutating any listed file makes verification fail.
- Changing a manifest record makes its signature verification fail.
- Changing the record chain but not recomputing/signing it is detected.
- Absolute and parent-traversal manifest paths are rejected.
- Unknown key/signature/digest algorithms are rejected.
- Oversized integers, floats, non-ASCII object keys, invalid Unicode, and excessive nesting are rejected by the restricted canonical JSON profile.

## 2. Protocol correctness scenarios (future adapters)

- Origin-only result identifies the earliest valid origin credential for one reported object according to the protocol definition.
- Path mode returns only the path permitted by the paper's definitions.
- Tree mode returns all and only the covered descendants and labels missing/unknown edges.
- Reports from recipients in different path depths; repeated forwarding; branching trees; merges where two independent origin copies share the same content.
- Duplicate content, exact-byte duplicates, text reformatting, copy/paste, screenshot, crop, recompression, transcription, attachment re-encoding, link preview, and message edits.
- Partial participation, offline clients, loss/reinstallation, linked devices, account migration, and device key rotation.

## 3. Adversarial protocol tests

- Forged origin or forward signature.
- Signature for one message/context replayed for another.
- Stale key after revocation, unknown key epoch, substituted provider key.
- Malicious server drops an edge or returns a truncated path.
- Server reorders messages, duplicates proofs, presents two different tree roots, forks transparency views, or suppresses revocation status.
- Colluding recipients/servers/authorities try to expose unreported messages.
- Request signed for one case/message/mode is replayed against another.
- Request has expiry in the past, future not-yet-valid interval, malformed target, overbroad scope, invalid signer or missing quorum participant.
- Single entity controls multiple nominal authority services.
- Sybil/brigading reporter creates multiple reports with correlated accounts.
- Compromised device key creates false forward claim.
- Provider phone binding begins/ends mid-investigation; number is reassigned after account closure.

## 4. Evidence-integrity tests

- Hash mismatch for original and derived artifact.
- Source file replaced after parsing.
- Symlink or path traversal escapes case directory.
- Malformed JSON/SQLite/file corruption is preserved as an acquisition fact rather than ignored.
- Parser version unknown: return unsupported, never partial success without warning.
- Manifest key differs from trusted key; self-signed trust explicitly shown.
- Timestamp token invalid, stale, wrong digest, wrong nonce, unknown policy, or revoked TSA certificate.
- Transparency inclusion proof invalid, consistency proof invalid, log fork detected by independent witnesses.
- Redaction output has a new hash and `derived_from` edge while original remains preserved.

## 5. Benchmark axes

- Forward-path length: 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024.
- Branching factor: 1, 2, 4, 8; depth/size kept separate.
- Tracing/anonymity thresholds for HTS: include permitted and rejected parameter sets.
- Number of participants, quorum threshold, availability failures, colluding participant subsets.
- Payload length/media type, number of devices per account, credential rotations.
- Report counts and false report rate; Sybil/correlated reporters.
- Client CPU, server CPU, bytes on wire, stored bytes, proof size, verifier cost, trace latency and memory.

Every benchmark run records commit hash, dependency lock, OS/CPU, input seed, parameters, warmup/repetitions, raw samples, aggregation script and errors. Compare confidence intervals/percentiles, not only means.

## 6. Release gates

No adapter may be promoted beyond `research-only` until its paper security model is encoded in tests, baseline results are reproduced within explainable tolerance, negative/adversarial tests pass, a second implementer reviews the code, and a cryptography/security reviewer signs off on the limitations. Production use also requires governance/legal review, operational threat modelling and incident response.
