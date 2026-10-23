# WhatsApp Traceability Research Lab unified benchmark schema v1

## Purpose

The benchmark command emits `opentrace.benchmark.v1` JSON records for the **synthetic Python research adapters** currently in the repository. It gives later protocol adapters a common envelope, but it is not evidence that the current adapters are byte-for-byte ports of any paper's construction.

## Run

```bash
opentrace benchmark \
  --message-size 256 \
  --max-hops 32 \
  --max-tree-depth 3 \
  --branching-factors 2,3 \
  --repeats 5 \
  --out artifacts/benchmark.json
```

Bounds: message size 1–1,000,000 bytes; path hop series drawn from 1, 2, 4, 8, 16, 32, 64, 128, 256 up to `--max-hops`; tree depth 1–6; branching factor 2–5; repeat count 1–100. Tree workloads grow exponentially, so raise depth and branching gradually.

## Report fields

- `schema`: report schema identifier.
- `environment`: Python version and platform string, useful for recording context rather than proving reproducibility.
- `method`: describes the timing source and synthetic inputs.
- `records[]`: one benchmark workload per path hop setting or tree `(depth, branching_factor)` tuple.
- `workload`: scenario shape and message byte length; the message contents are not saved in the report.
- `measurements`: median/minimum/maximum construction and trace nanoseconds, repeat count, adapter in-memory entry count, and compact-JSON serialized trace size.
- `samples_ns`: every observed construction and trace timing, in nanoseconds.
- `outcome`: correctness versus synthetic ground truth, scenario and recovered node/edge counts, a node-disclosure fraction, and the disclosure mode label.
- `summary`: number of records and count that reproduced expected synthetic graph structure.

## Interpretation cautions

1. Timings depend on machine load, Python version, the cryptographic package, and system configuration. Keep the environment block and samples when reporting numbers.
2. `serialized_trace_bytes` is the harness's compact JSON representation of identifiers and tree structure. It is **not** the bytes sent by a real protocol or any original Rust reference implementation.
3. `state_entries` counts in-memory dictionary entries, not actual memory footprint, persistent storage, platform retention, or storage per user.
4. `node_disclosure_fraction` measures only how many synthetic node IDs appear in the reconstructed path/tree relative to the known generated scenario. It does not quantify metadata inference, traffic analysis, legal exposure, or cryptographic anonymity.
5. Path and tree workloads intentionally differ in shape. Do not use a path record and a tree record as a controlled head-to-head protocol comparison.
6. The tree generator currently uses complete trees. Irregular trees, loss/reordering, malicious servers, collisions, compromised clients, collusion, and adversarial workloads require separate suites.
7. These adapters are marked `interoperable_with_reference: false`. Differential tests against the published Rust implementation and independent cryptographic review are still required.
8. The benchmark never queries accounts or messaging services and writes only synthetic integer identities to records.
