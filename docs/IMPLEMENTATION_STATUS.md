# Implementation Status — v0.6.0

This status file distinguishes code that is implemented from research directions, experimental prototypes, and deployment work that remains planned. “Implemented” means only that the local library/CLI, reproduction harness, schemas, and test suite cover the stated function; it is not a production security certification or proof of legal admissibility.

| Capability | Status in v0.6.0 | Evidence / Limitation |
|---|---|---|
| Synthetic origin/path/tree graph | Implemented | Explicit parent-edge traversal only; 100,000-event safety cap; never synthesizes speculative or absent historical edges. |
| Evidence manifest and integrity check | Implemented | Ed25519 signature, key fingerprint, SHA-256 digest/size, domain-separated record hash chain, schema, complete payload inventory. Key association still needs an external trust anchor. |
| Strict JSON parser | Implemented | Duplicate keys and non-standard constants rejected; file input capped at 16 MiB. |
| Configurable multi-approver decision | Implemented as a lab component | Request- and policy-bound Ed25519 signatures, strict policy/trust registry validation, safe relative key paths, signer roles/domains, public-key fingerprints, distinct domains, expiry, max validity, and allowed disclosure modes. Trust store/policy must be protected. Does not validate legal basis. Does not gate any production trace engine. Atomic one-time execution and replay registries remain pending for Phase 4. |
| Merkle inclusion proof | Implemented as offline lab | Uses RFC 9162 domain separation (leaf `0x00`, node `0x01`); proof is tested for sizes 1–19, with entry-count and size limits. No signed tree head, consistency proof, log service, witness, or split-view detection. |
| Local Merkle microbenchmark | Implemented | Measures this Python helper only (`benchmarks/benchmark_merkle.py`). |
| Unified path/tree benchmark | Implemented for synthetic adapters | Upgraded in v0.6.0 with formal methodology specification in `docs/BENCHMARKING.md`, Interquartile Range (IQR) dispersion metrics (`construction_ns_iqr`, `trace_ns_iqr`), and cross-platform hardware context disclosure (`machine`, `processor`, `cpu_count`, `total_memory_bytes`). 5 explicit interpretation boundaries formalize synthetic scope; no reference interoperability or production-performance claim. |
| One-command reproduction harness | Implemented in v0.6.0 | One-command reproduction script (`scripts/reproduce_all.py`, `docs/REPRODUCIBILITY.md`) executing 123 tests, generating 11 research artifacts, validating Draft 2020-12 schemas, verifying 4 epistemic/algorithmic invariants, asserting stable semantic baseline consistency, and emitting a cryptographic `reproduction-manifest.json`. |
| 2019 path traceback cryptographic scheme | Clean-room cryptographic reproduction implemented in v0.5.3 | Clean-room cryptographic implementation of the Path Traceback scheme from Tyagi, Miers, and Ristenpart (*ACM CCS 2019* / *ePrint 2019/981*) in `opentrace.protocols.traceback2019_crypto`. Features RFC-style domain-separated PRF, KDF, and AES-CTR stream cipher; recipient-view confidentiality strictly adhering to Theorem 2; Figure 3 missing-lookup termination; forwarder identity binding failing closed before key derivation or server table writes; full-table snapshot equality assertions; and optional `DeviceRegistry` PKI extension. Upstream differential testing against the Rust reference (`docs/REPRODUCING_TYAGI2019.md`) remains pending. |
| 2021 complaint-enabled source tracking | Synthetic model implemented | Source-only disclosure behavior is modeled; the CCS 2021 cryptographic construction remains unimplemented. |
| 2025 HTS | Synthetic threshold model implemented | Models source eligibility and the high-level threshold-gap result; no HTS signatures, proofs, or malicious-server game. |
| 2026 minimal-trust scheme | Synthetic policy-gate model implemented | Models report threshold, regulator, moderator, and platform gates, with an illustrative one-honest-role scenario matrix; no paper cryptography or proof. |
| RFC 8785 full canonicalization | Not implemented | Restricted no-floats profile in `canonical.py` only. Full JCS with official RFC 8785 vectors and cross-language fixtures is designated as the primary engineering foundation for Milestone v0.7.0. |
| RFC 3161 timestamp validation | Not implemented | Host time is not trusted time. |
| Signed transparency log | Not implemented | Needs signed tree heads, consistency proofs, independent monitoring/witnesses, and operational infrastructure. |
| WhatsApp integration/private-history lookup | Explicitly not supported | No account lookup, encryption bypass, backup decryption bypass, or historical forwarding-chain inference from a phone number. |
| Real digital-forensics artifact importer | Not implemented | Future work must be based on lawfully acquired supplied artifacts, documented versions, and external review. |

## Hosted CI & Test Suite Status (v0.6.0)

- The v0.6.0 suite reports **123 passing tests** with 100% cross-platform coverage across Python 3.11, 3.12, and 3.13 on Ubuntu, Windows, and macOS.
- Hosted GitHub Actions CI validates all 10 matrix and packaging jobs on every push and pull request:
  - 9 cross-platform test jobs covering Ubuntu, Windows, and macOS on Python 3.11, 3.12, and 3.13.
  - Packaging validation job building sdist, wheel, and source ZIP, running metadata checks via `twine`, and executing installed-distribution functional smoke tests in isolated virtual environments.
  - Tag-triggered release publication job rebuilding final artifacts, verifying SHA-256 checksums, and publishing release assets.
- Pre-publication release audit (`scripts/release_audit.py --require-release-date`) enforces 9 strict gates covering version agreement, CFF structure, Draft 2020-12 schema validation, current example reports, synthetic case signature verification, secret-marker scans, full-SHA GitHub Action pinning, and repository provenance.

## Known engineering limitations

- Local filesystem verification assumes a stable, non-hostile snapshot while verification runs. For a real forensic workflow, ingest into a controlled read-only workspace and protect against concurrent writes and path races.
- The trust registry and policy JSON are themselves trust anchors/configuration. The prototype does not sign or transparently publish them, manage revocation, or enforce one-time use across distributed instances. An atomic, persistent nonce registry and fail-closed replay prevention are roadmapped for Phase 4.
- Ed25519 and SHA-256 are classical algorithms; there is no PQC implementation in this release.
- JSON schemas are supplied, tested in CI, and verified by the reproduction harness and release audit, but the CLI does not yet enforce every schema before each operational write. Programmatic validators remain responsible for semantic validation.


---

## Historical Status — v0.5.2

The following section records the status at v0.5.2 for historical auditability and is preserved as an archival record:

- Synthetic 2019-style tree traceback adapter implemented. Branching regression test passes. Reference interoperability remains an open validation item.
- The v0.5.2 local suite reported 78 passing tests on Python 3.13. The nine-job hosted matrix and packaging job had not yet run prior to repository publication.


## Historical Status — v0.5.0

- Unified benchmark report schema: implemented for the synthetic Python path/tree adapters.
- Timing samples and median/min/max: implemented using `time.perf_counter_ns` over fresh runs.
- Ground-truth comparisons: implemented for generated synthetic linear paths and complete trees.
- Disclosure-size counters: counts returned identifiers/edges and fraction of scenario nodes; these are synthetic disclosure proxies, not a complete privacy proof.
- Adapter-state count: exposed as an in-memory entry count only; not an estimate of deployment database size.
- Reference differential testing: **not implemented**. No claim of equivalence to the 2019 Rust code was made.
- Faithful cryptographic implementations of the 2021 source-tracking, 2025 HTS, and 2026 minimal-trust schemes: **not implemented**. Impact Tracing remains a research direction.
- `opentrace compare` included five synthetic models: 2019 path, 2019 tree, 2021 source-only, 2025 HTS threshold model, and 2026 minimal-trust policy model.
- HTS records exposed threshold inputs, threshold gap, tracing eligibility, and a clearly labeled didactic payload-size proxy.
- Minimal-trust records exposed the four policy gates and a one-honest-role model matrix.


## Historical Status — v0.3.3 & v0.3.1

- Added a synthetic 2021 complaint-enabled source-tracking adapter demonstrating source-only disclosure with zero intermediate forwarders.
- Added synthetic 2019-style tree traceback adapter and branching regression tests.
