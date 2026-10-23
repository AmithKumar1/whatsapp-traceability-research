# Cryptography Decision Record

**Current release:** v0.5.2 (alpha research lab). Legacy `OpenTrace` domain-separation and serialized format identifiers are retained where changing them would invalidate existing fixtures or signed data.

## Active implementation profile

| Use | Selection | Reason / limitation |
|---|---|---|
| Evidence-file digest | SHA-256 | Interoperable digest with an explicit identifier. Digest match is integrity evidence, not proof that source claims are true. |
| Detached manifest signature | Ed25519 via `cryptography` | Mature, compact classical signature. A public key must be pinned through a separate trusted channel to identify its owner. |
| Evidence record hash links | SHA-256 with domain-separated prefix | Detects reordering/alteration within a signed manifest. The manifest signature and trusted key are essential; a local chain is not an externally witnessed transparency log. |
| Canonical encoding | WhatsApp Traceability Research Lab restricted canonical JSON v0.2 | Null, booleans, strings, lists, mappings, and safe integers; floats are rejected; object keys sort by UTF-16 code units. This improves Unicode interoperability but **is not a complete RFC 8785 implementation**. Do not claim general JCS interoperability. |
| Duplicate JSON properties | Rejected by strict parser | Duplicate property names can be interpreted differently by consumers and must not enter signed inputs. |
| Local Merkle inclusion proof | SHA-256 with `0x00` leaf / `0x01` node domain separation | Implements a local proof exercise following RFC 9162's tree-hash convention. It does not include a signed tree head, consistency proof, network log, or independent witness. |
| Authorization approvals | Ed25519 signatures bound to request digest, role, trust domain, and time | Demonstrates multi-party policy checks. Trust registry and policy require separate secure provisioning; this is not legal validation or proof that trust domains are genuinely independent. |
| Trusted time | Not implemented | Add RFC 3161 token validation later. Host clock timestamps are not trusted time. |
| External transparency log | Not implemented | An online service needs signed tree heads, consistency proofs, monitors/witnesses, log policy, and fork-detection operations. |
| Encryption at rest | Not implemented | Do not place sensitive live case material in repository artifacts. A future examiner environment needs OS/KMS-backed key management, least privilege, retention, deletion, and recovery controls. |

## Protocol layer: do not substitute cryptography casually

- Reuse a published scheme's required primitives and encodings exactly when reproducing it. Do not silently substitute Ed25519, SHA-256, KMAC, or another primitive where the paper requires something else.
- Treat `nirvantyagi/tracing` as an external reference baseline; pin a source commit/toolchain and audit license/dependencies before using or copying code.
- New signed objects must domain-separate their context and bind protocol/version, request/case ID, content commitment, credential/key epoch, role, time semantics, and disclosure mode where applicable.
- Prefer strict schemas, canonical encodings, cross-language test vectors, maintained cryptographic libraries, and constant-time library operations. No custom cryptographic arithmetic.

## Post-quantum migration path

NIST standardized three PQC algorithms: ML-KEM (FIPS 203), ML-DSA (FIPS 204), and SLH-DSA (FIPS 205). NIST SP 800-227, published in September 2025, provides guidance on KEM use. Their roles differ:

- **ML-KEM:** key establishment; not a signature scheme.
- **ML-DSA:** lattice-based digital signatures.
- **SLH-DSA:** stateless hash-based signatures.

NIST published errata planning notes for FIPS 203 and FIPS 204 in 2025/2026; re-check current errata before selecting a frozen profile. PQC migration needs wire encoding, certificate/key lifecycle, revocation, algorithm negotiation, downgrade prevention, historical validation, and performance budgets. Do not claim post-quantum security until an interoperable profile is implemented and tested. Do not invent hybrid composition ad hoc.

References: [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final), [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final), [FIPS 205](https://csrc.nist.gov/pubs/fips/205/final), [SP 800-227](https://csrc.nist.gov/pubs/sp/800/227/final).

## External evidence integrity options

- **RFC 3161 TSA:** validate a timestamp token, TSA certificate chain/policy, nonce, and status. It proves a digest existed no later than the TSA-asserted time under that trust policy; it does not prove message authorship/sending time or content truth.
- **RFC 9162-style log:** use Merkle inclusion and consistency proofs plus independent monitors/witnesses. A single operator may equivocate unless independent auditing detects inconsistent views.
- **C2PA:** validate signed media-asset provenance under its trust model. It does not prove the messaging account that forwarded the asset or the path between recipients.

## Key lifecycle requirements

Every deployed key type needs enrollment, binding, rotation, revocation, compromise declaration, and historical verification rules. Keep historical trust state for signature validation at a trusted time, subject to retention/privacy policy. Test emergency revocation, stale caches, lost devices, reinstall, phone-number reassignment, account migration, and old keys after revocation.

## Key-trust warning

A signature establishes that a message verifies under a public key. The association between that key and a claimed real-world signer is a separate assertion that must be established through a trusted provisioning and identity process. A key bundled beside its own signature is not its own trust anchor.
