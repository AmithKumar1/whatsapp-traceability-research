# WhatsApp Traceability Research Lab — Independent Research on E2EE Traceability

**Status:** research prototype / v0.5.2 · **License:** MIT · **As of:** 2026-10-23

**Repository:** https://github.com/AmithKumar1/whatsapp-traceability-research · **Issues:** https://github.com/AmithKumar1/whatsapp-traceability-research/issues · **Discussions:** https://github.com/AmithKumar1/whatsapp-traceability-research/discussions

**Python distribution:** `e2ee-traceability-lab`. The current alpha retains the `opentrace` Python module, `python -m opentrace` invocation, legacy `opentrace` console alias, and existing wire/schema identifiers for compatibility; the preferred installed CLI is `e2ee-traceability`.

Legacy `opentrace` names in serialized format identifiers and domain-separation strings are intentionally preserved for v0.x compatibility; they are protocol identifiers, not a second project name. The distribution name remains `e2ee-traceability-lab` for package compatibility; the project is now titled WhatsApp Traceability Research Lab.

WhatsApp Traceability Research Lab is an independent open-source research and evaluation framework for privacy-preserving source tracing in end-to-end encrypted (E2EE) messaging. It is designed to compare protocol families, test abuse resistance, preserve the provenance of evidence, and make uncertainty visible.

> **Independence and limits:** This is an independent research project, not affiliated with, endorsed by, or operated by WhatsApp/Meta. The current executable is a synthetic demonstration. It is not integrated with WhatsApp, does not reveal private chats, does not bypass encryption or backups, and cannot reconstruct historical forwarding events that were never recorded. Use real evidence only when lawfully acquired and authorized for examination.

## Why this project exists

There are several distinct research designs—not one generic “traceability algorithm”:

| Family | Primary capability | Research reference | Planned adapter status |
|---|---|---|---|
| Path / tree traceback | Reveal a path, or a forwarding tree, after a message is reported | Tyagi, Miers & Ristenpart, CCS 2019 | Reproduction study first |
| Complaint-enabled source tracking | Disclose a reported message's source while limiting disclosure of intermediate recipients | Peale, Eskandarian & Boneh, CCS 2021 | Specification/reproduction study |
| Hop Tracking Signatures (HTS) | Trace originators after long forwarding paths, with threshold-based anonymity | Branco et al., ePrint 2025/1052 | Synthetic threshold model; cryptographic reproduction pending |
| Minimal-trust source tracing | Distribute tracing power across distinct entities; limit abuse under collusion assumptions | Wang et al., NDSS 2026 | Synthetic policy-gate model; cryptographic reproduction pending |

WhatsApp Traceability Research Lab's novelty is intended to be the **reproducible comparison harness, policy model, evidence format, adversarial testing, and interoperability layer**, not a claim that all underlying cryptographic ideas are new.

## What works now

- `e2ee-traceability demo`: creates a synthetic branching forwarding graph.
- Evidence manifest v0.2: hashes file content and size, links records with a domain-separated SHA-256 record chain, signs a restricted canonical-JSON manifest with Ed25519, and checks bundle inventory completeness.
- `e2ee-traceability verify`: checks signature, signer-key fingerprint, record chain, payload sizes/digests, reserved paths, and unlisted files.
- `e2ee-traceability authorization-demo` / `e2ee-traceability authorize-check`: demonstration of request- and policy-bound Ed25519 approvals, strict policy/trust registry validation, safe relative public-key paths, configured roles, distinct approvers/trust domains, expiry, and disclosure-mode policy.
- `e2ee-traceability merkle-demo` / `e2ee-traceability merkle-verify`: create and independently verify offline Merkle inclusion proofs using RFC 9162-style leaf/node domain separation, with input-size safety limits and range-based tree hashing. `benchmarks/benchmark_merkle.py` reports reproducible local helper timings only.
- `e2ee-traceability traceback2019-benchmark`: run the focused synthetic path-traceback microbenchmark. It is explicitly non-interoperable with the upstream Rust reference until differential testing is completed.
- `e2ee-traceability benchmark`: run the unified synthetic path/tree harness with shared measurement schema, correctness checks, raw timing samples, disclosure counters, and workload bounds.
- `e2ee-traceability compare`: compare path/tree traceback, 2021 source-only tracking, HTS threshold behavior, and the 2026 minimal-trust policy model under a common report configuration.
- `e2ee-traceability hts2025-demo` and `e2ee-traceability minimal-trust2026-demo`: inspect the new conceptual models without contacting any messaging service.
- Strict JSON input parsing rejects duplicate object keys and non-standard numeric constants.
- Trace graph validation catches duplicate event IDs, missing parents, inconsistent content references, and cycles.
- Disclosure modes are explicit: `ORIGIN_ONLY` is the default; the demo stores separate synthetic `PATH` and `TREE` fixtures to test scope without silently disclosing them in the default report.
- Tests for successful verification and tampering detection.

The demo's key is self-signed and ephemeral. Without an independently trusted public key/fingerprint, it demonstrates consistency/integrity checking—not the real-world identity of the signer, a trustworthy time, or evidentiary admissibility. The authorization demo only verifies a configured technical policy; it does not validate a real court order or legal basis. The restricted canonical JSON profile rejects floating-point values and is not a full RFC 8785 implementation. The Merkle proof demo does not include a signed tree head or a network transparency service.

## Quick start

Requires Python 3.11+.

```bash
python -m venv .venv
# Windows PowerShell:
.venv\Scripts\Activate.ps1
# macOS/Linux:
# source .venv/bin/activate
python -m pip install -e ".[dev]"

e2ee-traceability demo --out ./artifacts/demo-case
e2ee-traceability verify ./artifacts/demo-case
e2ee-traceability authorization-demo --out ./artifacts/authorization-demo
e2ee-traceability authorize-check --request ./artifacts/authorization-demo/request.json --approvals ./artifacts/authorization-demo/approvals.json --trust ./artifacts/authorization-demo/trust-registry.json --policy ./artifacts/authorization-demo/policy.json
e2ee-traceability merkle-demo --out ./artifacts/merkle-proof.json
e2ee-traceability merkle-verify --proof ./artifacts/merkle-proof.json --entry-text synthetic-event-002
python benchmarks/benchmark_merkle.py --sizes 10 100 1000 --repeats 5 --out ./artifacts/merkle-benchmark.json
pytest
```

Or run without installing the entry point:

```bash
python -m opentrace demo --out ./artifacts/demo-case
python -m opentrace verify ./artifacts/demo-case
```

To verify against a **separately trusted** public key, pass it explicitly:

```bash
e2ee-traceability verify ./artifacts/demo-case --public-key ./trusted-signer.pem
```

The trusted key must be obtained through a separate trusted channel. A public key bundled next to a manifest is not its own trust anchor.

## Project principles

1. **First originator is not necessarily a named human.** A cryptographic account credential, device, phone-number binding, and real-world person are different claims.
2. **First-originator mode is the default.** Full path/tree disclosure is a more invasive, separately authorized mode.
3. **No evidence, no claim.** Every report finding should link to evidence, a verification method, and limitations.
4. **Observed ≠ verified ≠ inferred.** Reports use explicit epistemic labels.
5. **No phone-number lookup of private histories.** Evidence adapters accept user-provided or lawfully acquired artifacts; they do not access an account just from a number.
6. **Cryptography is not a substitute for governance.** Authorization, scope minimization, multi-party control, audit, revocation, and appeal are first-class design surfaces.
7. **No home-grown cryptographic primitives.** Reuse mature libraries and standard encodings; isolate research algorithms behind adapters.
8. **Do not overclaim time.** Device timestamps, platform timestamps, trusted timestamp tokens, and inferred ordering are distinct.
9. **Blockchain is optional, not magic.** Prefer portable signed manifests and append-only transparency proofs; no public blockchain is required for MVP.
10. **Do not deploy protocol adapters as production tracing until independently reviewed.**

## Repository map

```text
src/opentrace/
  README.md
  pyproject.toml
  docs/
    MASTER_SPEC.md
    RESEARCH_REVIEW.md
    THREAT_MODEL.md
    ARCHITECTURE.md
    DATA_MODEL.md
    CRYPTO_DECISIONS.md
    LEGAL_AND_ETHICAL_SCOPE.md
    TEST_PLAN.md
    ROADMAP.md
    DECISIONS.md
    PROTOCOL_ADAPTERS.md
    REPRODUCIBILITY.md
    GITHUB_RELEASE_CHECKLIST.md
  schemas/
    trace-event.schema.json
    case-manifest.schema.json
    authorization-request.schema.json
    authorization-approval.schema.json
    authorization-approvals.schema.json
    authorization-policy.schema.json
    trust-registry.schema.json
    merkle-inclusion-proof.schema.json
    benchmark-report.schema.json
  src/opentrace/
    canonical.py
    strictjson.py
    tracegraph.py
    integrity.py
    authorization.py
    authorization_demo.py
    transparency.py
    protocols/traceback2019.py
    protocols/traceback2019_tree.py
    protocols/source_tracking2021.py
    protocols/hts2025.py
    protocols/minimal_trust2026.py
    comparison.py
    benchmark.py
    demo.py
    cli.py
  tests/
  examples/
```

Release 0.5.2 example comparison outputs are in `examples/protocol-comparison-sample-v0.5.2.json` and `examples/protocol-comparison-sample-v0.5.2.md`. These timings are machine-dependent demonstrations of the Python harness, not cryptographic benchmarks.

## Research references

The source-by-source review, including what each paper contributes and what WhatsApp Traceability Research Lab should not assume from it, lives in [`docs/RESEARCH_REVIEW.md`](docs/RESEARCH_REVIEW.md). Protocol-specific implementation should begin only after reproducing and documenting the papers' threat models and security definitions.

## Roadmap summary

- **P0:** synthetic event graph + signed evidence manifest + tests — v0.1.
- **P1:** hardened local manifest, configurable multi-approver policy, offline Merkle inclusion proofs, strict JSON, expanded adversarial tests — v0.2.
- **P2:** formal schemas, confidence/claim model, benchmark harness, property-based tests.
- **P2:** independent reproduction of published schemes, each in a separate adapter.
- **P3:** distributed authorization, quorum policy, transparency and timestamp integration.
- **P4:** authorized evidence importers and case-report export.
- **P5:** external cryptography review, formal analysis, and research paper.

See [`docs/ROADMAP.md`](docs/ROADMAP.md) for release gates.

## Security reporting

Do not publish exploit details or personal data in public issues. See [`SECURITY.md`](SECURITY.md) for responsible disclosure.


## 0.3.1 research additions

- Added a synthetic 2019-style tree-traceback adapter.
- Added a branching-tree regression test and `opentrace traceback2019-tree-demo`.
- The adapter is research-only and explicitly non-interoperable with production messengers.
- The 2019 reference implementation remains the differential-testing target; WhatsApp Traceability Research Lab does not claim cryptographic equivalence until vector-by-vector comparison is completed.


## Unified synthetic benchmark (v0.3.3)

Run the path and tree adapters with shared report fields:

```bash
opentrace benchmark --message-size 256 --max-hops 32 --max-tree-depth 3 --branching-factors 2,3 --repeats 5 --out artifacts/benchmark.json
```

The JSON report records construction/trace timing samples and summaries, synthetic correctness checks, scenario/recovered nodes and edges, in-memory adapter entries, and a compact JSON output-size proxy. Read [`docs/BENCHMARK_SCHEMA.md`](docs/BENCHMARK_SCHEMA.md) before comparing results.

**Research limitation:** the Python adapters are not yet proven interoperable with the original Rust reference. These timings are not production performance claims, and path-versus-tree runs use different topology shapes.

## Protocol comparison (v0.5.2)

WhatsApp Traceability Research Lab 0.5 compares five synthetic research models in one report:

```bash
opentrace compare \
  --message-size 256 \
  --hops 8 \
  --tree-depth 3 \
  --branching-factor 2 \
  --repeats 5 \
  --hts-anonymity-threshold-hops 2 \
  --hts-trace-threshold-hops 4 \
  --out artifacts/protocol-comparison.json \
  --markdown artifacts/protocol-comparison.md
```

The comparison covers source recovery, intermediate-hop disclosure, full-tree disclosure, complaint requirements, timing, output size, synthetic state, and trust/authorization assumptions. HTS threshold settings are configurable. All adapters are explicitly marked **synthetic** and **non-interoperable**. HTS payload-size outputs are didactic proxies, not measured signature sizes; minimal-trust gates are simulated, not cryptographically enforced.

See `docs/PROTOCOL_COMPARISON.md` and `schemas/protocol-comparison.schema.json`.

The two new demos are:

```bash
opentrace hts2025-demo --hops 8 --anonymity-threshold-hops 2 --trace-threshold-hops 4
opentrace minimal-trust2026-demo --required-reports 3
```

They translate only high-level research properties into testable behavior; they do **not** implement the papers' cryptographic schemes.
