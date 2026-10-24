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
- **Traceback Termination & Sentinel Semantics:**
  - In Figure 3, the originator samples $k_0$ and a sentinel origin predecessor key $k_{\text{prev}} = \text{ORIGIN\_KEY} = 0^{256}$ (or samples a random dummy predecessor key with no corresponding entry in the server table $T$).
  - When the platform executes backward traversal, reaching the sentinel key $k = \text{ORIGIN\_KEY}$ or encountering an address $F(k_{\text{prev}}, m)$ absent from $T$ signals that the origin has been reached, terminating traceback cleanly.
- **Third-Party Deniability:** Because all cryptographic material is symmetric, both sender and receiver possess $k$ and $\text{mid}$. No non-repudiable asymmetric digital signatures are created that could prove authorship to an external third party or court. Accountability is internal to the platform via authenticated transmission sessions.

### 1.2 Experimental Non-Repudiation Extension (DeviceRegistry PKI)
As an optional extension beyond the paper's symmetric design, senders may attach an Ed25519 digital signature over the tag payload. To prevent identity spoofing:
- Verifiers **must not** accept a sender identity merely because the public key supplied alongside the record verifies a signature.
- An authenticated `DeviceRegistry` is required to bind `(account_id, device_id)` pairs to authorized public keys. Self-asserted public keys not present in the registry are rejected.

### 1.3 Epistemic Boundary & Identity Disambiguation
- **Account Identifier (`acct:*`):** Platform user handle in the messaging network.
- **Device Identifier (`dev:*`) & Public Key:** Endpoint cryptographic credentials.
- **Human Operator:** Cryptographic verification establishes only key possession by a device credential; it does **not** prove who physically typed the message, held the handset, or authorized transmission.
- **Absence of Phantom Edges:** If a forwarding record is missing or expired, the protocol halts at the break and emits `missing_forwarding_record_in_server_state`. It strictly refrains from manufacturing speculative forwarding links.

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
| **Absence of Phantom Edges** | Missing records cause immediate explicit termination, no speculative edges synthesized. | `termination_reason = "missing_forwarding_record_in_server_state"` | `test_default_symmetric_mode_without_signatures()` |
| **Cycle Detection** | Traversal terminates safely if forwarding pointers form a loop. | `visited_keys` set in `trace()` | `test_cyclic_forwarding_actually_exercises_loop_and_terminates()` |

---

## 4. Documented Deterministic Test Vector (Known-Answer Test)

To ensure reproducibility across independent implementations, a fixed deterministic test vector is provided with hardcoded 32-byte hexadecimal seeds and independently asserted Known-Answer Test (KAT) outputs:

- **Message ($m$):** `b"Tyagi 2019 fixed test vector payload"`
- **Alice Private Key Seed:** `1111111111111111111111111111111111111111111111111111111111111111`
- **Bob Private Key Seed:** `2222222222222222222222222222222222222222222222222222222222222222`
- **Origin Tracing Key ($k_0$):** `0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20`
- **Origin Predecessor Key:** `0000000000000000000000000000000000000000000000000000000000000000` (32 zero bytes)
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

## 7. Deviations, Upstream Status & Future Milestones

### Upstream Reference Implementation Status
- Upstream prototype: [`nirvantyagi/tracing`](https://github.com/nirvantyagi/tracing) (Rust / C dependencies, Redis server backend).
- **Differential Interoperability Status:** Not yet completed. Direct binary differential testing requires a native Rust nightly toolchain and a running Redis instance, which are outside the pure offline Python scope of this repository. This Python implementation is a **clean-room cryptographic reproduction** following the paper's documented algorithms.

### Next Concrete Research Milestones
1. **Tree-Traceback Cryptographic Extension:** Extend from linear path traceback to branching tree topologies.
2. **Threshold Reporting:** Evaluate multi-complaint quorum requirements for intermediate node disclosure.
3. **Upstream Differential Harness:** Create an automated CI container with native Rust/Redis to execute cross-language differential test vectors against `nirvantyagi/tracing`.
