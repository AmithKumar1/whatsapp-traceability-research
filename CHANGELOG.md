# Changelog

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
