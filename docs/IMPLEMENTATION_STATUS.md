# Implementation Status — v0.5.2

This status file distinguishes code that is implemented from research directions and deployment work that remains planned. “Implemented” means only that the local library/CLI and tests cover the stated function; it is not a production security certification.

| Capability | Status in 0.5.2 | Evidence / limitation |
|---|---|---|
| Synthetic origin/path/tree graph | Implemented | Explicit parent-edge traversal only; 100,000-event safety cap; never fills absent historical edges. |
| Evidence manifest and integrity check | Implemented | Ed25519 signature, key fingerprint, SHA-256 digest/size, record hash chain, schema, complete payload inventory. Key association still needs an external trust anchor. |
| Strict JSON parser | Implemented | Duplicate keys and non-standard constants rejected; file input capped at 16 MiB. |
| Configurable multi-approver decision | Implemented as a lab component | Request- and policy-bound signatures, strict policy/trust registry validation, safe relative key paths, signer roles/domains, public-key fingerprints, distinct domains, expiry, max validity, and allowed disclosure modes. Trust store/policy must be protected. Does not validate legal basis. Does not gate any production trace engine. |
| Merkle inclusion proof | Implemented as offline lab | Uses RFC 9162-style domain separation; proof is tested for sizes 1–19, with entry-count and size limits. No signed tree head, consistency proof, log service, witness, or split-view detection. |
| Local Merkle microbenchmark | Implemented | Measures this Python helper only. |
| Unified path/tree benchmark | Implemented for synthetic adapters | Measures local Python adapter timings and synthetic disclosure proxies; no reference interoperability or production-performance claim. |
| RFC 8785 full canonicalization | Not implemented | Restricted no-floats profile only. Full JCS + official vectors is a release gate. |
| RFC 3161 timestamp validation | Not implemented | Host time is not trusted time. |
| Signed transparency log | Not implemented | Needs signed tree heads, consistency proofs, independent monitoring/witnesses, and operations. |
| 2019 path/tree cryptographic scheme | Not implemented | Must be independently reproduced and benchmarked from the existing Rust reference. |
| 2021 complaint-enabled source tracking | Synthetic model implemented | Source-only disclosure behavior is modeled; the CCS 2021 cryptographic construction remains unimplemented. |
| 2025 HTS | Synthetic threshold model implemented | Models source eligibility and the high-level threshold-gap result; no HTS signatures, proofs, or malicious-server game. |
| 2026 minimal-trust scheme | Synthetic policy-gate model implemented | Models report threshold, regulator, moderator, and platform gates; no paper cryptography or proof. |
| WhatsApp integration/private-history lookup | Explicitly not supported | No account lookup, encryption bypass, backup decryption bypass, or historical forwarding-chain inference from a phone number. |
| Real digital-forensics artifact importer | Not implemented | Future work must be based on lawfully acquired supplied artifacts, documented versions, and external review. |

## Known engineering limitations

- Local filesystem verification assumes a stable, non-hostile snapshot while verification runs. For a real forensic workflow, ingest into a controlled read-only workspace and protect against concurrent writes and path races.
- The trust registry and policy JSON are themselves trust anchors/configuration. The prototype does not sign or transparently publish them, manage revocation, or enforce one-time use across distributed instances.
- Ed25519 and SHA-256 are classical algorithms; there is no PQC implementation in this release.
- JSON schemas are supplied and tested in CI, but the CLI does not yet enforce every schema before each operation. Programmatic validators remain responsible for semantic validation.


### 0.3.1
- Synthetic 2019-style tree traceback adapter implemented.
- Branching regression test passes.
- Reference interoperability remains an explicit open validation item.


## v0.5.0 comparison status (historical)

- Unified benchmark report schema: implemented for the synthetic Python path/tree adapters.
- Timing samples and median/min/max: implemented using `time.perf_counter_ns` over fresh runs.
- Ground-truth comparisons: implemented for generated synthetic linear paths and complete trees.
- Disclosure-size counters: counts returned identifiers/edges and fraction of scenario nodes; these are synthetic disclosure proxies, not a complete privacy proof.
- Adapter-state count: exposed as an in-memory entry count only; not an estimate of deployment database size.
- Reference differential testing: **not implemented**. No claim of equivalence to the 2019 Rust code is made.
- Faithful cryptographic implementations of the 2021 source-tracking, 2025 HTS, and 2026 minimal-trust schemes: **not implemented**. Impact Tracing remains a research direction.

## v0.3.3 research adapter (retained in v0.5.0)

- Added a **synthetic 2021 complaint-enabled source-tracking adapter**.
- Demonstrates the source-only disclosure property: an authorized complaint resolves the originating account while exposing zero intermediate forwarders in the model.
- This is a research abstraction, **not** a cryptographic reimplementation or interoperable implementation of the CCS 2021 construction.
- Added tamper-rejection tests and CLI demo: `opentrace source-tracking2021-demo`.


## v0.5.0 comparison expansion

- `opentrace compare` now includes five synthetic models: 2019 path, 2019 tree, 2021 source-only, 2025 HTS threshold model, and 2026 minimal-trust policy model.
- HTS records expose threshold inputs, threshold gap, tracing eligibility, and a clearly labeled didactic payload-size proxy. Do not interpret the proxy as a real signature size.
- Minimal-trust records expose the four policy gates and a one-honest-role model matrix. These tests are not a proof of the paper's security property.
- All comparison records remain `synthetic`; no production messenger integration or paper-level cryptographic interoperability is implemented.
- The v0.5.2 local suite reports 78 passing tests on Python 3.13. The nine-job hosted matrix and packaging job have not yet run; their results must be checked after the real repository URL is added to `CITATION.cff`.
