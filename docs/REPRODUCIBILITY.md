# Researcher Reproducibility & Independent Evaluation Guide

Canonical repository: https://github.com/AmithKumar1/whatsapp-traceability-research  
Target Release: **v0.5.3** (Commit `58dd59fb48dc1fe1b9e2a1f9156bb740cf45d068`) / **v0.6.0** Development  
Scope: Offline cryptographic path traceback reproduction, multi-protocol research comparison, and benchmark replication.

---

## 1. Quickstart: One-Command Reproduction

An independent researcher can reproduce all project benchmarks, cryptographic experiments, and invariant checks from a clean repository checkout with a single command:

```bash
python scripts/reproduce_all.py
```

For quick verification with reduced hop counts and iterations:

```bash
python scripts/reproduce_all.py --quick
```

### What the Harness Executes
1. **Automated Test Suite:** Runs the full 120-test test suite (`pytest -q`).
2. **Experiment & Benchmark Generation:** Generates Tyagi et al. (*ACM CCS 2019*) path traceback experiment reports (honest and adversarial scenarios), multi-protocol comparison reports, benchmark reports, Merkle inclusion proofs, and synthetic evidence demo cases.
3. **JSON Schema Validation:** Validates all generated JSON artifacts against canonical Draft 2020-12 schemas in `schemas/`.
4. **Epistemic & Research Invariant Verification:** Verifies candidate-vs-verified origin separation, recipient-view confidentiality (Theorem 2), forwarder identity binding with server snapshot equality, and non-interoperability disclaimers.
5. **Stable Semantic Comparison:** Compares stable structural semantics against committed release baselines (`examples/protocol-comparison-sample-v0.5.3.json`).
6. **Reproduction Manifest Generation:** Emits `artifacts/reproduction/reproduction-manifest.json` recording environment details, source git revision, execution results, and SHA-256 hashes of all generated artifacts.

---

## 2. Clean-Room Environment Setup

To ensure exact reproducibility, use Python 3.11, 3.12, or 3.13 in an isolated virtual environment:

### Step 1: Clone Repository
```bash
git clone https://github.com/AmithKumar1/whatsapp-traceability-research.git
cd whatsapp-traceability-research
git checkout main
```

### Step 2: Create & Activate Virtual Environment
```bash
# On Linux/macOS
python3 -m venv .venv
source .venv/bin/activate

# On Windows PowerShell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

### Step 3: Install Pinned Dependencies
```bash
python -m pip install --upgrade pip
python -m pip install -e .
python -m pip install -r requirements-dev.txt
```

Verify your environment meets direct tool requirements:
- `cryptography == 50.0.2`
- `pytest == 9.1.1`
- `jsonschema >= 4.23.0`
- `ruff == 0.14.2`
- `mypy == 1.18.2`

---

## 3. Generated Artifacts & Structure

Running `python scripts/reproduce_all.py` creates `artifacts/reproduction/` containing:

| Artifact | Type | Description |
| :--- | :--- | :--- |
| `traceback-experiment.json` | JSON | Tyagi et al. (CCS 2019) 4-hop linear path experiment (honest baseline) |
| `traceback-experiment.md` | Markdown | Rendered experimental findings and cryptographic measurement report |
| `traceback-adversarial-tampered.json` | JSON | Adversarial evaluation with tampered content (fails closed) |
| `traceback-adversarial-missing.json` | JSON | Adversarial evaluation with missing predecessor lookup (terminates cleanly) |
| `protocol-comparison.json` | JSON | Comparative evaluation across all five synthetic traceability models |
| `protocol-comparison.md` | Markdown | Rendered multi-protocol matrix report |
| `benchmark-report.json` | JSON | Microbenchmarking timings and storage entries across synthetic adapters |
| `merkle-inclusion-proof.json` | JSON | RFC 9162-style offline Merkle inclusion proof and root validation |
| `demo-case/manifest.json` | JSON | Signed synthetic evidence manifest with Ed25519 signature |
| `hts2025-demo.json` | JSON | Hop Tracking Signatures (ePrint 2025/1052) threshold model evaluation |
| `minimal-trust2026-demo.json` | JSON | Four-gate policy simulation evaluation |
| `reproduction-manifest.json` | JSON | Run record containing git commit, OS, Python version, and SHA-256 hashes |

---

## 4. Stable Semantics vs. Randomized Execution

A key requirement in cryptographic research evaluation is avoiding false-positive divergence:

1. **Non-Deterministic Elements:**
   - **Timestamps:** ISO-8601 UTC creation timestamps vary on every invocation.
   - **Cryptographic Keys & Nonces:** Per-message tracing keys ($k, k_{\text{prev}} \leftarrow \{0, 1\}^{256}$) and AES-CTR nonces are generated using cryptographically secure PRNGs (`os.urandom`) and differ every run.
   - **System Performance Timers:** Raw execution timings (`perf_counter_ns`) naturally fluctuate depending on CPU architecture, governor, and OS scheduling.
2. **Stable Invariants Checked:**
   - Schema validation against Draft 2020-12 meta-schemas.
   - Protocol counts ($N=5$) and adapter identifiers.
   - Qualitative capability flags (`finds_source`, `reveals_intermediate_hops`, `disclosure_mode`).
   - Outcome classifications (`SUCCESS`, `FAILED_VERIFICATION`, `TERMINATED_AT_MISSING_LOOKUP`).
   - Epistemic separation between unverified candidate forwarders and certified originators.

The reproduction harness deliberately compares **stable semantics**, ensuring that tests confirm mathematical and algorithmic fidelity without forcing pseudo-random test keys into production paths.

---

## 5. Epistemic Boundaries & Research Invariants

External researchers evaluating this implementation should inspect four core invariants:

### Invariant 1: Candidate Origin vs. Ground-Truth Verified Origin
- Protocol-level traversal discovers an earliest identifiable forwarding node (`candidate_origin_account`, `candidate_origin_device`).
- The protocol marks this as an **unverified candidate claim**.
- Ground-truth origin certification (`recovered_origin_account`, `recovered_origin_device`) is established solely when validated against an independent oracle or ground-truth simulator.
- Under content tampering, the protocol fails closed (`FAILED_VERIFICATION`) and explicitly sets `recovered_origin_account = None`.

### Invariant 2: Recipient-View Confidentiality (Tyagi et al., Theorem 2)
- Theorem 2 states that message recipients learn nothing about prior forwarding history.
- Predecessor pointer ciphertexts ($c_{\text{ptr}} = \text{AES-CTR}(K_{\text{enc}}, k_{\text{prev}})$) are stored exclusively in the server state table and never included in the recipient envelope (`MessageEnvelope`).

### Invariant 3: Forwarder Identity Binding
- In `forward_message()`, the sender’s account and device IDs are checked against the recipient recorded in `ReceivedMessageState`.
- Any mismatch raises `ForwarderIdentityMismatchError` before key derivation, signing, or modifying the server table.
- Server table snapshot comparison proves zero state mutation occurred on rejection.

### Invariant 4: Non-Interoperability & Synthetic Scope
- All five protocol adapters are synthetic, non-interoperable models.
- `summary["interoperable_protocols"] == []` across all comparison outputs.
- No live WhatsApp network integration, private key exfiltration, or backdoors exist.

---

## 6. Benchmarking Methodology

Benchmark measurements should adhere to the following protocol:

- **Workload Scenarios:**
  - **Linear Forwarding:** Chains of length $L \in \{2, 4, 8, 16, 32\}$.
  - **Tree Forwarding:** Trees of depth $D \in \{2, 3, 4\}$ with branching factor $B \in \{2, 3\}$.
- **Measurements:**
  - Setup and device key generation time ($\text{ns}$).
  - Forwarding key derivation and tag construction time ($\text{ns}$).
  - Reverse traversal / trace reconstruction time ($\text{ns}$).
  - Storage footprint: Server table entry count and byte size.
  - Envelope overhead: Per-hop tag bytes transmitted over the network.
- **Reporting:** Report median values across at least 5 repeated trials to minimize CPU frequency scaling jitter.

---

## 7. Independent Checksum & Tag Verification

### Verifying Published Release Assets
For any official release (e.g., `v0.5.3`), download the published distribution assets and verify their SHA-256 hashes:

```bash
# Using GitHub CLI
gh release download v0.5.3

# On Linux/macOS
sha256sum -c e2ee-traceability-lab-v0.5.3.sha256

# On Windows PowerShell
Get-FileHash -Algorithm SHA256 e2ee_traceability_lab-0.5.3-py3-none-any.whl
Get-FileHash -Algorithm SHA256 e2ee_traceability_lab-0.5.3.tar.gz
Get-FileHash -Algorithm SHA256 e2ee-traceability-lab-v0.5.3-source.zip
```

### Verifying Reproduction Artifacts
The reproduction harness records file hashes in `reproduction-manifest.json`. You can verify artifact integrity using Python:

```bash
python -c "
import json, hashlib, pathlib
m = json.loads(pathlib.Path('artifacts/reproduction/reproduction-manifest.json').read_text())
for k, v in m['artifacts'].items():
    p = pathlib.Path('artifacts/reproduction') / v['relative_path']
    h = hashlib.sha256(p.read_bytes()).hexdigest()
    assert h == v['sha256'], f'Hash mismatch on {k}'
print('All reproduced artifact checksums verified!')
"
```

---

## 8. Discrepancy Reporting Template

If an independent evaluation produces discrepancies, please log an issue with the following template:

```markdown
### Environment
- OS / Platform: [e.g., Ubuntu 24.04 LTS / macOS 15.0 / Windows 11]
- Python version: [e.g., Python 3.12.3]
- Commit hash: [e.g., 58dd59fb48dc1fe1b9e2a1f9156bb740cf45d068]

### Reproduction Step
- Command executed: [e.g., python scripts/reproduce_all.py]

### Discrepancy Observed
- Expected outcome: [e.g., Invariant 2 PASS]
- Observed outcome: [e.g., Invariant 2 FAIL with error message]

### Attached Manifest
- Attach `artifacts/reproduction/reproduction-manifest.json`
```
