# Examples

Run `opentrace demo --out ./artifacts/demo-case` to generate a synthetic case bundle. It contains pseudonymous IDs such as `acct:synthetic-A`, never real contact details.

Do not place real chat exports, device images, or private case files in this public examples directory. Future evidence examples must be synthetic or use redistributable consented datasets.

Run `opentrace authorization-demo --out ./artifacts/authorization-demo` to produce a fresh, expiring synthetic request and two signed approvals. Verify them using `opentrace authorize-check` as shown in the root README. Do not commit a generated authorization fixture: it expires and is a synthetic trust example only.

Run `opentrace merkle-demo --out ./artifacts/merkle-proof.json` followed by `opentrace merkle-verify --proof ./artifacts/merkle-proof.json --entry-text synthetic-event-002` to generate and independently verify a sample inclusion proof. The proof root is not signed by a transparency log.


`benchmark-sample-2026-10-23.json` is one local synthetic run from the stated environment, included for format/reproducibility illustration only. Timings are not a performance claim and will vary by machine. Re-run `python benchmarks/benchmark_merkle.py --sizes 10 100 1000 10000 --repeats 5 --out ./artifacts/merkle-benchmark.json` for your own environment.


## v0.6.0 protocol comparison examples

- `protocol-comparison-sample-v0.6.0.json` and `.md` compare the five synthetic adapters using one bounded run. Local timing fields are illustrative only.
- `hts2025-demo-sample-v0.6.0.json` shows the HTS threshold model. Its `didactic_payload_size_proxy_bytes` is **not** a real signature-size estimate.
- `minimal-trust2026-demo-sample-v0.6.0.json` shows the four-gate policy simulator and one-honest-role examples. These are not a proof of cryptographic abuse resistance.


## Historical examples (v0.5.3, v0.5.2)

- `protocol-comparison-sample-v0.5.3.json` and `.md`
- `hts2025-demo-sample-v0.5.3.json`
- `minimal-trust2026-demo-sample-v0.5.3.json`

- `protocol-comparison-sample-v0.5.2.json` and `.md`
- `hts2025-demo-sample-v0.5.2.json`
- `minimal-trust2026-demo-sample-v0.5.2.json`

All files contain synthetic account labels and test data only. Never replace them with private message exports or real account identifiers.
