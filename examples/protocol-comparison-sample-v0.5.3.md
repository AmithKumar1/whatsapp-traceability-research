# WhatsApp Traceability Research Lab Protocol Comparison

> Research comparison only. Current adapters are synthetic and are not wire-compatible with deployed messaging systems.

## Scenario

- Message size: **256 bytes**
- Linear path: **8 hops**
- Tree: **depth 3 / branching 2**
- Repeats: **5**

## Comparison

| Protocol | Source | Intermediate hops | Full tree | Complaint | Disclosure | Trace median | Output bytes |
|---|---:|---:|---:|---:|---|---:|---:|
| `traceback2019-synthetic-path` | yes | yes | no | no | `path` | 77700 ns | 61 |
| `traceback2019-synthetic-tree` | yes | yes | yes | no | `full_synthetic_forwarding_tree` | 248900 ns | 380 |
| `source-tracking2021-synthetic` | yes | no | no | yes | `source_only` | 1800 ns | 60 |
| `hts-2025-synthetic` | yes | no | no | no | `source_only_after_hop_threshold` | 3000 ns | 112 |
| `minimal-trust-2026-synthetic` | yes | no | no | yes | `source_only_after_policy_gates` | 3600 ns | 86 |

## Interpretation

- **Path traceback** is useful when the research question is the chain from a reported recipient back toward the source.
- **Tree traceback** trades greater disclosure for visibility into the synthetic forwarding tree.
- **Source-only tracking** minimizes forwarding disclosure: the model resolves the source under a complaint without returning intermediate hops.
- **HTS threshold modeling** illustrates the published threshold-gap result; its payload-size proxy is pedagogical, not a measured signature size or cryptographic implementation.
- **Minimal-trust modeling** gates disclosure on reports, a regulator blocklist decision, moderator approval, and platform release authorization; gates are simulated rather than cryptographically enforced.
- A protocol marked **synthetic** must not be presented as interoperable with WhatsApp, Signal, or another production messenger.

## Security interpretation

These measurements compare this laboratory's models, not real-world cryptographic security. Production claims require a faithful specification, formal security analysis, independent implementation review, test vectors, and interoperability testing.
