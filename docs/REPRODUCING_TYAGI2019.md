# Reproducing Tyagi et al. (CCS 2019): Path Traceback Cryptographic Reproduction

This document specifies the cryptographic design, security theorems, implementation mapping, recipient-side verification lifecycle, and experimental results for the clean-room cryptographic reproduction of the Path Traceback construction introduced in:

> **Reference:** Nirvan Tyagi, Ian Miers, and Thomas Ristenpart.  
> *"Traceback for End-to-End Encrypted Messaging."*  
> **ACM Conference on Computer and Communications Security (CCS 2019)** / **IACR Cryptology ePrint Archive Report 2019/981**.  
> URL: https://eprint.iacr.org/2019/981.pdf

---

## 1. Background, Symmetric Design & Third-Party Deniability

Tyagi et al. designed cryptographic traceback schemes allowing a messaging platform or moderator, upon receiving an authenticated user complaint containing a forwarded message and cryptographic tag, to trace the path backwards hop-by-hop to the origin sender—without allowing the platform to decrypt message contents or trace uncomplained messages.

### 1.1 The Published Construction: Symmetric Cryptography, Server Separation & Deniability
In Section 4 and Figure 3 of the paper, the Path Traceback scheme is designed using **symmetric cryptographic techniques**:
- Each hop uses a fresh random symmetric **tracing key** $k \in \{0, 1\}^{256}$.
- The message is tagged with a keyed message identifier $\text{mid} = F(k, m)$ computed via a collision-resistant pseudorandom function (CR-PRF).
- A symmetric encryption key $K_{\text{enc}} = H(k)$ is derived using a key derivation function.
- The predecessor tracing key $k_{\text{prev}}$ is encrypted as an encrypted pointer $c_{\text{ptr}} = \text{AES-CTR}(K_{\text{enc}}, k_{\text{prev}})$.
- **Strict Protocol Separation (Theorem 2 User Trace Confidentiality):**
  - **Platform storage table:** The server stores $T[\text{mid}] = (\text{sender}, \text{receiver}, c_{\text{ptr}})$.
  - **Recipient message envelope:** Over the E2EE channel, the recipient receives strictly $(m, k, \text{mid})$. Predecessor pointer ciphertexts $c_{\text{ptr}}$ are **never delivered to recipients**.
  - Because $K_{\text{enc}} = H(k)$, any recipient in possession of both $k$ and $c_{\text{ptr}}$ could decrypt $k_{\text{prev}} = \text{Dec}(K_{\text{enc}}, c_{\text{ptr}})$ and recursively expose earlier forwarding history. Isolating $c_{\text{ptr}}$ exclusively to the server guarantees that recipients learn only the immediate message content and tracing key, and cannot inspect previous forwarding history.
- **Traceback Termination Semantics (Figure 3):**
  - In Figure 3, the originator samples fresh random tracing key $k_0 \leftarrow \{0, 1\}^{256}$ and a fresh random dummy predecessor key $k_{\text{prev}} \leftarrow \{0, 1\}^{256}$ (not a fixed zero sentinel). The predecessor key is encrypted as $c_{\text{ptr}} = \text{AES-CTR}(H(k_0), k_{\text{prev}})$ and stored in $T[\text{mid}_0]$.
  - Crucially, no record is created for $F(k_{\text{prev}}, m)$ in $T$.
  - When the platform executes backward traversal, reaching an address $F(k_{\text{prev}}, m)$ absent from $T$ signals the end of recorded forwarding, terminating traceback.
  - **Epistemic Principle (Normal Origin vs. Missing Evidence):** Because an originator-sampled random predecessor key and a missing/pruned intermediate forwarding record both result in $T[\text{mid}] = \bot$, an absent lookup in server state identifies a putative/candidate origin, but **never proves that the true origin was reached**. If intermediate records were pruned, expired, or dropped, traceback terminates at the earliest available intermediate forwarder.
- **Third-Party Deniability:** Because all cryptographic material is symmetric, both sender and receiver possess $k$ and $\text{mid}$. No non-repudiable asymmetric digital signatures are created that could prove authorship to an external third party or court. Accountability is internal to the platform via authenticated transmission sessions.

### 1.2 Experimental Non-Repudiation Extension (DeviceRegistry PKI)
As an optional extension beyond the paper's symmetric design, senders may attach an Ed25519 digital signature over the tag payload. To prevent identity spoofing, downgrade attacks, and link tampering:
- **Registry Fail-Closed:** Verifiers **must not** accept a sender identity merely because the public key supplied alongside the record verifies a signature. An authenticated `DeviceRegistry` is required to bind `(account_id, device_id)` pairs to authorized public keys. Self-asserted public keys not present in the registry are rejected.
- **Downgrade & Signature-Stripping Protection:** When PKI mode is required (`require_signature=True`), unsigned envelopes and server records are immediately rejected (`RecMsgVerificationError` / `missing_required_signature_in_pki_mode`).
- **Predecessor Pointer Integrity Binding:** The signature payload binds `ct_digest = H(c_ptr)` alongside `mid`, `message_digest`, and identity strings. This authenticates the predecessor pointer against platform or MITM tampering, while keeping the raw predecessor ciphertext $c_{	ext{ptr}}$ off the recipient's envelope to strictly preserve CCS 2019 Theorem 2 User Trace Confidentiality.

### 1.3 Epistemic Boundary & Identity Disambiguation
- **Account Identifier (`acct:*`):** Platform user handle in the messaging network.
- **Device Identifier (`dev:*`) & Public Key:** Endpoint cryptographic credentials.
- **Human Operator:** Cryptographic verification establishes only key possession by a device credential; it does **not** prove who physically typed the message, held the handset, or authorized transmission.
- **Absence of Phantom Edges & Candidate Reporting:** If an intermediate record is pruned or expired, the protocol halts at the break and reports an unverified candidate origin in `candidate_origin_account` (`predecessor_record_absent_candidate_origin_unverified`). It strictly refrains from manufacturing speculative forwarding links, and reserves `recovered_origin_account` exclusively for candidates certified by ground truth.

---

## 2. Recipient-Side Verification (`RecMsg`)

A critical component of the published protocol (Section 4, Figure 3) is the explicit **recipient-side verification algorithm (`RecMsg`)**:

1. When a client receives a message envelope $(m, k, \text{mid}, \dots)$ over the E2EE channel, it **must verify** the binding before accepting the message or allowing it to be forwarded:
   $$\text{expected\_mid} = F(k, m)$$
   $$\text{Verify: } \text{expected\_mid} \stackrel{?}{=} \text{mid}$$
2. If $\text{expected\_mid} \neq \text{mid}$, `RecMsg` immediately raises `RecMsgVerificationError` and rejects the delivery.
3. If the non-repudiation extension is active, `RecMsg` verifies the sender's public key against the `DeviceRegistry` and verifies the attached signature.
4. Messages that fail `RecMsg` cannot be forwarded, preventing corrupted or manipulated tracing state from propagating downstream.

---

## 3. Formal Security Theorems & Claim-to-Code Mapping

| Formal Property / Theorem | Paper Definition | Code Implementation | Automated Test & Verification |
| :--- | :--- | :--- | :--- |
| **Platform Trace Confidentiality** | **CCS 2019 Theorem 1:** Uncomplained messages and forwarding paths are computationally indistinguishable from random to the messaging platform under PRF and stream-cipher security. | Server table stores pseudorandom `mid` addresses and AES-CTR encrypted pointers. | `test_crypto_primitives_invertible_and_deterministic()` |
| **User Trace Confidentiality** | **CCS 2019 Theorem 2:** Recipients cannot determine prior message history, originator identity, or preceding tracing keys from their local view. Predecessor ciphertexts $c_{\text{ptr}}$ remain exclusively platform-side. | `MessageEnvelope` and `ReceivedMessageState` omit `ct`; ciphertexts reside strictly in `ServerStorageRecord`. | `test_recipient_view_confidentiality_no_predecessor_pointer_exposure()` |
| **Trace Unforgeability (Framing Resistance)** | **CCS 2019 Theorem 3:** Adversary cannot frame an honest user as the originator of an unauthored message under PRF collision resistance and authenticated routing. | Authenticated delivery routing + `RecMsg` binding + optional `DeviceRegistry` PKI extension | `test_unregistered_self_asserted_key_rejected()`, `test_corrupt_signature_aborts_forwarding_before_downstream_hops()` |
| **Path Soundness** | Backward traversal across honest forwarding chain recovers origin sender and device. | `CryptographicTracebackServer.trace()` | `test_canonical_symmetric_path_traceback_reaches_origin()`, `test_default_symmetric_mode_without_signatures()` |
| **Recipient Binding & Wrong-Message Termination** | Recipient `RecMsg` verification binds $m$, $k$, and $\text{mid}$; altering $m$ halts traceback. | `rec_msg()` and mid verification | `test_tampered_content_aborts_forwarding_before_downstream_hops()`, `test_recipient_rec_msg_lifecycle_and_tamper_rejection()` |
| **Absence of Phantom Edges** | Missing or pruned records cause immediate explicit termination, reporting an unverified candidate; no speculative edges synthesized. | `termination_reason = "predecessor_record_absent_candidate_origin_unverified"` | `test_missing_intermediate_record_terminates_at_intermediate_forwarder()`, `test_missing_hop_experiment_scenario()` |
| **Cycle Detection** | Traversal terminates safely if forwarding pointers form a loop; resets candidate origin. | `visited_keys` set in `trace()` | `test_cyclic_forwarding_actually_exercises_loop_and_terminates()` |
| **Duplicate Identifier Rejection** | Svr-Process rejects duplicate message identifiers `mid` to prevent key reuse anomalies. | `process_delivery() == False` raises `DuplicateMessageIdentifierError` | `test_duplicate_message_identifier_rejected()` |
| **Predecessor Pointer Authentication** | In PKI mode, $H(c_{\text{ptr}})$ is bound into the signature to detect server-side link tampering. | `_compute_extension_payload(..., ct_digest)` | `test_tampered_predecessor_pointer_fails_signature_in_pki_mode()` |
| **Signature Downgrade Resistance** | PKI mode requires signatures on every hop; stripped signatures fail closed. | `require_signature=True` in `rec_msg` and `trace` | `test_signature_stripping_downgrade_rejected()` |

---

## 4. Documented Deterministic Test Vector (Known-Answer Test)

To ensure reproducibility across independent implementations, a fixed deterministic test vector is provided with hardcoded 32-byte hexadecimal seeds and independently asserted Known-Answer Test (KAT) outputs:

- **Message ($m$):** `b"Tyagi 2019 fixed test vector payload"`
- **Alice Private Key Seed:** `1111111111111111111111111111111111111111111111111111111111111111`
- **Bob Private Key Seed:** `2222222222222222222222222222222222222222222222222222222222222222`
- **Origin Tracing Key ($k_0$):** `0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20`
- **Origin Predecessor Key ($k_{\\text{prev}, 0}$, Fixed KAT Seed):** `0000000000000000000000000000000000000000000000000000000000000000` (32-byte fixed test seed for KAT verification; standard operation samples $k_{\\text{prev}}$ uniformly at random)
- **Expected Message Identifier ($\text{mid}_0$, Hex KAT):**  
  `9e35b1b5fb0a7dc8f56cb8eb622affc53f2f47e7cad89db802c1c16f727b3482`
- **Expected Encryption Key ($K_{\text{enc}, 0}$, Hex KAT):**  
  `bc82b29e544be8de92d327c92a41d2dd`
- **Expected Pointer Ciphertext ($c_{\text{ptr}, 0}$, Hex KAT):**  
  `ebdfe9c438a26a7dd6dfcea304e8785e8a68281862836df7d3ec34a8733dd205`

Verified in `tests/test_traceback2019_reproduction.py::test_fixed_deterministic_test_vector`.

---

## 5. Execution & Reproduction Commands

### Run Automated Tests
```powershell
python -m pytest tests/test_traceback2019_reproduction.py -v
```

### Run Full Test Suite & Release Audit
```powershell
python -m pytest -q
python -m ruff check .
python -m mypy src tests
python scripts/release_audit.py
```

### Execute CLI Experiment (JSON + Markdown Output)
```powershell
python -m opentrace traceback-reproduction --hops 4 --out artifacts/exp_valid.json --markdown artifacts/exp_valid.md
```

### Test Adversarial Scenarios
```powershell
# Forged signature / identity spoofing rejection
python -m opentrace traceback-reproduction --hops 4 --scenario forged_signature --adversarial-hop 2

# Tampered message content rejection (RecMsg / tracer halt)
python -m opentrace traceback-reproduction --hops 4 --scenario tampered_content --adversarial-hop 2

# Broken forwarding chain (absence of phantom edges)
python -m opentrace traceback-reproduction --hops 4 --scenario missing_hop --adversarial-hop 2

# Cyclic forwarding loop detection
python -m opentrace traceback-reproduction --hops 4 --scenario cyclic_forwarding --adversarial-hop 2
```

---

## 6. Experimental Observations & Synthetic Timings Caveat

> [!NOTE]
> **Microbenchmarks vs. Published Network Measurements**
> The timings produced by this offline testbed measure pure local in-process microbenchmarks on synthetic hardware. They demonstrate algorithmic scaling and relative overheads, but **are not directly comparable** to the wide-area network (WAN) and simulated distributed messaging latencies reported in Tyagi et al. 2019.

- **Local Traceback Latency:** < 1 millisecond for 4 hops (in-memory lookup + symmetric decryption).
- **Per-Hop Wire Tag Overhead:** 64 bytes in purely symmetric canonical mode; 160 bytes with optional Ed25519 PKI extension.
- **Server Record Storage:** In-memory dictionary indexed by 32-byte `mid`.

---

## 7. Deviations, Upstream Status & Reference Differential Testing

### Upstream Reference Implementation Status & Oracle Pinning
- **Upstream prototype:** [`nirvantyagi/tracing`](https://github.com/nirvantyagi/tracing) pinned to immutable Git commit SHA [`24644f73fae82c1f6f4d7daea4f24638ecfd060b`](https://github.com/nirvantyagi/tracing/tree/24644f73fae82c1f6f4d7daea4f24638ecfd060b).
- **Oracle Harness & Provenance:** See [`docs/STAGE2_DIFFERENTIAL_ASSESSMENT.md`](STAGE2_DIFFERENTIAL_ASSESSMENT.md) and [`tools/upstream_oracle/PROVENANCE.md`](../tools/upstream_oracle/PROVENANCE.md).
- **Differential Interoperability Status:** The current Python implementation is a **clean-room, paper-informed cryptographic reproduction**, not a byte-compatible wire clone of the upstream prototype. All differences are classified as `KNOWN_PROFILE_DIVERGENCE` in [`tests/test_upstream_differential.py`](../tests/test_upstream_differential.py) and verified against deterministic oracle vectors in [`tests/data/oracle/tyagi2019_rust_oracle_vectors.json`](../tests/data/oracle/tyagi2019_rust_oracle_vectors.json).

### Profile Comparison Matrix

| Component | Current Python Profile (`traceback2019_crypto`) | Upstream Rust Prototype (`nirvantyagi/tracing`) | Classification |
| :--- | :--- | :--- | :--- |
| **Tracing Key Size** | 32 bytes (256-bit symmetric key per paper Section 4) | 16 bytes (128-bit key) | `KNOWN_PROFILE_DIVERGENCE` |
| **Message Identifier (`mid`)** | `HMAC-SHA-256` with domain prefix (`Tyagi2019-PRF-mid-v1\x00`) | `HMAC-SHA3-256` without domain prefix | `KNOWN_PROFILE_DIVERGENCE` |
| **Pointer Encryption** | `AES-128-CTR` with `HMAC-SHA256` KDF ($K_{\text{enc}} = H(k)$) | Raw `AES-128-ECB` single-block encrypt under key $k$ | `KNOWN_PROFILE_DIVERGENCE` |
| **Origin Predecessor Key** | Originator-sampled random dummy key $k_{\text{prev}}$ (Figure 3) | Fixed 16-byte zero sentinel (`[0; 16]`) | `KNOWN_PROFILE_DIVERGENCE` |
| **Participant Identities** | String URIs (`acct:*`, `dev:*`) with optional Ed25519 PKI | Integer routing IDs (`u32`) without digital signatures | `KNOWN_PROFILE_DIVERGENCE` |
| **Storage Model** | In-memory verified storage with duplicate rejection | Redis hash-map store (`ct`, `sid`, `rid`) | `KNOWN_PROFILE_DIVERGENCE` |

### Next Concrete Research Milestones
1. **Tree-Traceback Cryptographic Extension:** Extend from linear path traceback to branching tree topologies.
2. **Threshold Reporting:** Evaluate multi-complaint quorum requirements for intermediate node disclosure.
3. **Optional Upstream Compatibility Profile:** Evaluate whether a dedicated compatibility mode (`--profile upstream-rust`) is warranted after the differential test baseline is established.
