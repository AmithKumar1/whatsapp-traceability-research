# Roadmap

## Phase 0 — v0.1 scaffold (complete)

**Deliverables:** repository structure; synthetic chain/tree graph; restricted canonical encoding; Ed25519-signed file manifest; SHA-256 digest and record hash chain; CLI; tests; research/architecture/threat-model documentation.

**Exit criteria:** `pytest` passes; changed evidence is detected; docs make clear that no real WhatsApp trace or forensic extraction is implemented.

## Phase 1 — harden the research harness (partially complete in v0.2)

- Add JSON Schema validation to CLI and CI (next).
- [Configured in v0.5.2] Expand CI coverage to Python 3.11–3.13 across Ubuntu, Windows, and macOS; hosted results remain a publication gate.
- Add structured typed result/error format and report versioning.
- Expand `benchmarks/` from the local Merkle microbenchmark to the synthetic trace-graph harness and publish fixed-seed results.
- Add cross-language golden JSON proof/report fixtures and property-based/fuzz tests.
- Replace the restricted canonicalizer with a maintained, fully RFC 8785-conformant implementation; pass published test vectors before protocol adapters sign arbitrary JSON.
- Establish project name/trademark check before first public announcement.

## Phase 2 — reproduce the 2019 baseline

- Clone original implementation into an isolated worktree/submodule or use a clean-room reimplementation after license review.
- Pin commit, compiler/toolchain, dependencies and Redis version if needed.
- Reproduce path/tree test outputs and benchmarks from paper.
- Audit known compatibility issues and security assumptions.
- Create a claim-to-code table and describe each deviation.
- Keep tree mode off by default in UI demos due disclosure breadth.

## Phase 3 — source-only and newer protocol comparisons

- Reproduce the 2021 complaint-enabled source-tracking construction.
- **Done for v0.5:** add a didactic 2025 HTS threshold-gap model and parameter validation; faithful cryptographic syntax and proof behavior remain pending.
- **Done for v0.5:** add a four-gate minimal-trust policy simulator and a one-honest-role test matrix; paper-level cryptographic construction and formal guarantees remain pending.
- Ensure each adapter has its own key formats, proof formats, parameter file and security profile.

## Phase 4 — authorization, quorum, audit (policy core prototype exists)

- Signed authorization request with strict scope and expiry (current request schema is signed indirectly by approval signatures).
- Multi-party signatures bound to an identical request digest; operational one-time execution/replay registry still needed.
- Key/certificate validation, explicit trust-store pinning, and revocation state.
- Append-only audit records and operator/witness split.
- Negative tests for invalid, overbroad, stale and colluding requests.
- No legal-policy module ships without qualified jurisdictional review.

## Phase 5 — verifiable timestamps and transparency (local Merkle proof lab exists)

- RFC 3161 timestamp client/verifier.
- RFC 9162 consistency proofs and independent monitor/witness tooling; the current code only demonstrates local inclusion proofs.
- Signed tree heads and log-key lifecycle.
- Demonstrate how a log fork is detected across independently gathered views.

## Phase 6 — authorized evidence imports

- Generic evidence manifest and importer API.
- User-supplied export adapter with provenance and parser-version metadata.
- SQLite artifact adapter for a supplied authorized database, with read-only operation and schema-version detection.
- Desktop/Web artifact adapters only for clearly documented versions and lawful acquisition methods.
- C2PA 2.4 validation adapter for media; keep claims separate from message forwarding proof.
- Importer conformance suite with malformed/corrupt inputs.

## Phase 7 — PQC and interoperability research

- Profiles for ML-DSA/SLH-DSA signatures and ML-KEM where key establishment is relevant.
- Key/certificate/encoding migration and rollback resistance.
- Cost/size/performance comparison against classical profile.
- Investigate (do not assume) whether post-quantum properties are useful for each protocol adapter's threat horizon.

## Phase 8 — external review and public research release

- Independent security review and responsible disclosure policy.
- Reproduction package, datasets with synthetic identifiers, benchmark scripts and result tables.
- Protocol limitations, ethics analysis and policy tradeoffs.
- Research paper documenting negative results and implementation deviations, not only successful demos.

## Recommended order

Do not start by implementing all the papers simultaneously. First get the synthetic demo/tests into CI, then reproduce the 2019 baseline, compare the 2021 source-only approach, and add HTS/minimal-trust models with each paper's exact assumptions. Authorization and trust infrastructure should evolve in parallel with the protocol lab, never afterthoughts.
