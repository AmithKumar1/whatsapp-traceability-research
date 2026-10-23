# WhatsApp Traceability Research Lab Protocol Comparison Engine

WhatsApp Traceability Research Lab 0.5 compares five **synthetic** research models under a bounded test scenario:

1. 2019-style path traceback
2. 2019-style tree traceback
3. 2021-style complaint-enabled source-only tracking
4. 2025 HTS threshold behavior
5. 2026 minimal-trust policy-gate behavior

## Run

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

The JSON output follows `schemas/protocol-comparison.schema.json`.

## What it measures

The harness normalizes source recovery, intermediate-hop disclosure, tree disclosure, complaint/policy requirements, local construction/trace timing, serialized trace/output size, synthetic state-entry counts, and correctness against the toy model's expected result. HTS measurements include thresholds, threshold gap, eligibility, and a pedagogical payload-size proxy. Minimal-trust measurements include the required policy gates and the outcome of a four-role illustrative scenario matrix.

## How to interpret it

- **Timings are Python model execution timings**, not protocol benchmarks. Different model shapes mean they should not be used for performance rankings.
- `proof_or_trace_bytes` is the serialized output from this laboratory model, not the bandwidth of a production protocol.
- `didactic_payload_size_proxy_bytes` is a deliberately toy value used to illustrate the shape of a threshold-gap result. It is not HTS signature size.
- `storage_entries` counts simple in-memory model records when the adapter has such state. It is not a production storage estimate.
- Capability profiles represent the research family at a high level; they do not show that this code implements its cryptography.
- All current records are `reference_status: synthetic`. No adapter is interoperable with WhatsApp, Signal, or the paper implementations.

## CLI demonstrations

```bash
opentrace hts2025-demo --hops 8 --anonymity-threshold-hops 2 --trace-threshold-hops 4
opentrace minimal-trust2026-demo --required-reports 3
```

See [`HTS2025_ADAPTER.md`](HTS2025_ADAPTER.md) and [`MINIMAL_TRUST2026_ADAPTER.md`](MINIMAL_TRUST2026_ADAPTER.md) for model scope, research references, and work required before a faithful reproduction claim.

## Research-readiness checklist

A future cryptographic adapter should not be marked `reference` until its algorithm, assumptions, threat model, and test vectors match the cited work. It should not be marked `interoperable` until independent implementations agree over published or independently reviewed vectors. A production messenger integration additionally requires an explicit lawful authorization model, scope minimization, auditability, key transparency, operational controls, and privacy review.
