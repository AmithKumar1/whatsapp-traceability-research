# Changelog

## 0.6.0 — 2026-10-24

- Implemented Milestone v0.6.0 Reproducibility Harness (`scripts/reproduce_all.py`), generating 11 verified research artifacts across path traceback, cross-protocol comparison, benchmarks, offline Merkle proofs, and policy simulations.
- Added programmatic algorithmic and epistemic research invariants verifying candidate-vs-verified origin separation, recipient-view confidentiality (CCS 2019 Theorem 2), forwarder identity binding with server table snapshot invariance, and synthetic non-interoperability verification.
- Added stable semantic baseline comparison tool (`compare_semantic_baseline`) to isolate deterministic protocol properties and qualitative capabilities from machine CPU timing jitter.
- Published comprehensive researcher reproducibility guide (`docs/REPRODUCIBILITY.md`) detailing clean-room setup, schema checks, and artifact verification.
- Formalized benchmark methodology in `docs/BENCHMARKING.md`, defining standardized linear path series ($L \in \{1, 2, 4, 8, 16, 32\}$) and tree workloads ($D \in \{1, 2, 3\}$, $B \in \{2, 3\}$).
- Added Interquartile Range (IQR) dispersion metrics (`construction_ns_iqr`, `trace_ns_iqr`) to `src/opentrace/benchmark.py` and `schemas/benchmark-report.schema.json` to capture latency variance.
- Added cross-platform hardware context collection (`machine`, `processor`, `cpu_count`, `total_memory_bytes`) across Linux, Windows, and macOS.
- Documented 5 essential interpretation boundaries governing benchmark results, data schemas, and research adapter constraints.
- Expanded test suite to 123 passing unit tests with 100% cross-platform coverage across Python 3.11, 3.12, and 3.13.
- Refreshed all current-version example reports, schemas, release audit tooling, and release documentation for v0.6.0.

## 0.5.3 — 2026-10-24

- Added a clean-room cryptographic reproduction of the Path Traceback scheme from Tyagi, Miers, and Ristenpart (*ACM CCS 2019* / *ePrint 2019/981*), including RFC-style domain-separated PRF, KDF, and AES-CTR primitives, recipient-view confidentiality (Theorem 2), and Figure 3 missing-lookup termination.
- Established strict epistemic separation between protocol-level unverified candidate origins (`candidate_origin_account`, `candidate_origin_device`) and ground-truth verified origins (`recovered_origin_account`, `recovered_origin_device`).
- Implemented protocol forwarder identity binding in `forward_message()`, raising `ForwarderIdentityMismatchError` before key derivation, signing, or modifying server table state.
- Hardened canonical serialization in `_compute_extension_payload()` with 4-byte big-endian length prefixing and explicit NUL byte rejection.
- Added comprehensive regression and invariance test suites, including full-table snapshot equality assertions, PKI downgrade and signature-stripping protections, and known-answer tests.
- Bumped build backend pins to `setuptools==84.2.1` and `wheel==0.48.0` in `pyproject.toml`.
- Bumped development/test tool pins to `cryptography==50.0.2` and `pytest==9.1.1` in `requirements-dev.txt`.
- Refreshed all current-version example reports and release documentation for v0.5.3.

## 0.5.2 — 2026-10-23

- Added a strict release audit for project/version/citation consistency, structural CFF/YAML validation, JSON Schema meta-validation, current example validation, signed synthetic-bundle verification, high-confidence secret-marker scans, workflow SHA pinning, and cross-platform matrix presence. The local suite includes release-gate regression coverage, including tests for citation parsing, workflow structure, and refusal to build final artifacts before release metadata is complete.
- Added a release build helper that runs the audit before producing distributions, checks distribution metadata, creates a source ZIP, and writes SHA-256 checksums.
- Isolated pre-repository candidate outputs so they cannot silently overwrite or masquerade as final-release artifacts.
- Expanded the publishing guide and release checklist with explicit repository-identity, hosted-CI, provenance, and artifact-rebuild gates.
- Refreshed all current-version example reports and release metadata for v0.5.2; retained historical version notes as historical records.
- Reaffirmed that the source-tracing protocol adapters are synthetic research models and not interoperable cryptographic implementations.

## 0.5.1 — 2026-10-23

- Corrected remaining release metadata and historical-document references for the WhatsApp Traceability Research Lab rebrand.
- Added a dedicated packaging-validation CI job and `scripts/build_release.py` to build the sdist/wheel/source ZIP, check metadata, run installed wheel/sdist functional smoke tests, and generate checksums only after the strict release audit passes.
- Added Dependabot configuration for Python dependencies and GitHub Actions.
- Regenerated v0.5.1 synthetic example reports and release artifacts after metadata changes.
- Removed `date-released` from unreleased citation metadata; added an explicit release-date audit gate so candidate metadata does not falsely claim a publication date. The canonical repository URL remains an owner-specific blocker until the repository exists.

## 0.5.0 — 2026-10-23

- Rebranded the public project and Python distribution as **WhatsApp Traceability Research Lab** / `e2ee-traceability-lab`; added the `e2ee-traceability` CLI while retaining the `opentrace` module and legacy CLI alias for alpha compatibility.
- Expanded CI smoke coverage for all five synthetic adapters, schema validation for generated reports, and explicit checks that no adapter is marked interoperable.
- Pinned GitHub Actions workflow dependencies to verified full commit SHAs and added a repository-publication guide.
- Pinned current direct test/build tools in `requirements-dev.txt`; it is intentionally documented as not being a fully transitive lockfile.
- Regenerated the bundled synthetic evidence demo and signature after the public-facing report heading changed; the case now verifies cleanly.
- Added the `hts-2025-synthetic` threshold model for Hop Tracking Signatures research, including explicit anonymity/trace thresholds and the threshold-gap relationship described by ePrint 2025/1052.
- Added the `minimal-trust-2026-synthetic` policy model with verified-report threshold, regulator blocklist, moderator approval, and platform release gates.
- Added an illustrative one-honest-role scenario matrix for platform, regulator, moderator, and recipients; each scenario is labeled as a policy simulation, not a cryptographic guarantee.
- Expanded `opentrace compare` to five research models and added HTS threshold options.
- Added `opentrace hts2025-demo` and `opentrace minimal-trust2026-demo`.
- Normalized source-only disclosure counters against the configured linear path size.
- Added regression tests and research notes linked to the published papers.
- All newly added adapters remain synthetic and non-interoperable; no paper's cryptographic construction is claimed as implemented.

## 0.4.0 - Protocol Comparison Engine

- Added a common traceability-adapter comparison layer.
- Added normalized capability profiles for the 2019 path/tree and 2021 source-only research models.
- Added controlled cross-protocol timing, disclosure, output-size, and synthetic-state measurements.
- Added `opentrace compare` CLI command.
- Added JSON Schema for protocol comparison reports.
- Added Markdown comparison report generation.
- Explicitly marks current adapters as synthetic/non-interoperable.


## 0.3.2 — 2026-10-23

- Added a unified benchmark report schema covering synthetic path and tree adapters.
- Added shared workload metadata, median/min/max timings, raw timing samples, in-memory state-entry counts, and compact serialized trace-size proxies.
- Added correctness checks against generated synthetic ground truth and disclosed-node/edge counts.
- Added `opentrace benchmark` with bounds on message size, hop count, tree depth, branching factor, and repeats.
- Explicitly labels results as synthetic, non-interoperable, machine-dependent research measurements; it does not claim reference-protocol wire compatibility.
- Added benchmark-harness regression tests and a generated sample report.


## 0.2.0 — 2026-10-23

- Upgraded the signed evidence manifest to v0.2 with file sizes, signer-key fingerprint pinning, strict field validation, full payload inventory checks, path hardening, symlink rejection, and a 10,000-record limit.
- Added strict JSON loading (duplicate object keys and NaN/Infinity rejected).
- Improved restricted canonical JSON key sorting to use UTF-16 code-unit order; floating-point values still fail closed and the profile is not a full RFC 8785 implementation.
- Added experimental request-bound Ed25519 approval verification with role/trust-domain binding, minimum distinct approvers/domains, request expiry, maximum validity, and disclosure-mode policy.
- Added an offline Merkle inclusion-proof lab using RFC 9162-style hash domain separation, bounded input sizes, range-based tree hashing, and a reproducible microbenchmark.
- Hardened the authorization policy lab with strict policy/trust-registry schemas, policy-digest binding, safe relative public-key paths, and exact disclosure scope.
- Added complete schemas for authorization requests, individual approvals, approval bundles, policies, trust registries, and proof records, all validated offline.
- Added `CITATION.cff`, GitHub issue templates, and source-distribution metadata for a more reproducible open-source release.
- Added schemas and adversarial tests for tampering, duplicate JSON keys, approval replay/tampering, scope mismatch, expiry, trust-domain mismatch, and Merkle proofs for tree sizes 1–19.
- No production WhatsApp integration and no paper's cryptographic tracing scheme is claimed as implemented.

## 0.1.0 — 2026-10-23

- Initial synthetic trace graph, signed evidence manifest prototype, research notes, threat model, and CLI.
