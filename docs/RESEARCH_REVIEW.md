# Research Review and Technology Map

**Checked:** 2026-10-23. This is a curated engineering map, not an exhaustive systematic literature review. Verify the latest paper version, repository status, and terms before implementation.

## 1. Cryptographic source-tracing research

### A. Tyagi, Miers & Ristenpart (CCS 2019): *Traceback for End-to-End Encrypted Messaging*

- Paper: https://eprint.iacr.org/2019/981
- Open implementation: https://github.com/nirvantyagi/tracing
- Functionality: path traceback and tree traceback for reported E2EE messages. The paper describes tracing tags/pointers and discusses preserving privacy for unreported messages.
- Practical value: the repository is a useful baseline for reproduction and benchmarking rather than a reason to start from zero. It contains a Rust workspace with library and server crates; its README notes server builds require nightly Rust and tests use Redis.
- Limitations to assess: age of dependencies/toolchain; exact security properties vs newer designs; deployment/storage metadata; multi-server trust; abuse authorization; how it handles real-world transformations, client compromise, key rotation, incomplete branches, and provider/phone-number identity binding.
- Implementation plan: run in a sandbox, pin the source commit and toolchain, reproduce paper benchmarks first, audit licenses/dependencies, then record all deviations before creating the adapter.

### B. Peale, Eskandarian & Boneh (CCS 2021): *Secure Complaint-Enabled Source-Tracking for Encrypted Messaging*

- Paper: https://doi.org/10.1145/3460120.3484539 (also reported at https://crypto.unc.edu/papers/src_tracking.pdf)
- Research question: how to enable source tracking through a complaint process while improving disclosure/privacy properties compared with revealing an entire forwarding path.
- Design points to examine: complaint enablement, source disclosure, intermediate-recipient confidentiality, tree-linkable vs tree-unlinkable variants, deniability, unforgeability, platform storage, and dependence on platform components.
- Implementation plan: obtain the canonical version and any companion code/test vectors; translate the game-based definitions into explicit adapter guarantees; do not infer performance or production support from the abstract alone.

### C. Branco, Green, Hegde, Jain & Kaptchuk (ePrint 2025/1052): *How to Trace Viral Content in End-to-End Encrypted Messaging*

- Paper: https://eprint.iacr.org/2025/1052
- The paper introduces Hop Tracking Signatures (HTS) for originator tracing over long forwarding paths, targeting anonymity for others and security against malicious servers.
- Important theoretical result: succinct constructions are not possible when tracing and anonymity thresholds differ by exactly one hop under their model; a larger gap can permit succinct schemes whose signature size does not grow with the forwarding path, relying on streaming algorithms and strong assumptions.
- Adapter implications: parameter validation is security-critical; expose `trace_threshold`, `anonymity_threshold`, path semantics, and leakage as explicit config. Benchmark both proof/signature size and trace latency; model malicious servers. Treat this as a preprint unless a peer-reviewed version is confirmed.
- Do not generalize the positive result outside the paper's exact syntax, assumptions, or threshold conditions.

### D. Wang et al. (NDSS 2026): *Abuse Resistant Traceability with Minimal Trust for Encrypted Messaging Systems*

- Paper/abstract: https://www.ndss-symposium.org/ndss-paper/abuse-resistant-traceability-with-minimal-trust-for-encrypted-messaging-systems/
- PDF: https://www.ndss-symposium.org/wp-content/uploads/2026-f456-paper.pdf
- Main ideas: distribute traceability across distinct real-world entities; target minimal trust (traceability cannot be abused as long as one participant remains honest, even if others collude) and minimal information disclosure. The authors report an implementation using techniques deployed by Signal and comparable performance to approaches they describe as more abuse-prone.
- Adapter implications: model each party as a genuinely distinct trust domain, require quorum contributions bound to the same case/request/scope, and test every meaningful collusion subset. Multiple processes or cloud accounts under one administrator do not meet the real-world independence assumption.
- Critical review questions: what is assumed about entity identity/independence, report thresholds, Sybil resistance, key revocation, message transformation, availability, and the exact proof that one honest party is sufficient?

## 2. Standards and interoperable components

### RFC 9420 — Messaging Layer Security (MLS)

- https://www.rfc-editor.org/rfc/rfc9420.html
- MLS is a standardized group end-to-end encryption protocol with tree-based group state and cipher suites. It is a possible basis for a synthetic test messenger; it is not itself a source-tracing/traceback protocol and should not be described as WhatsApp's protocol.
- OpenMLS is an open-source Rust implementation: https://github.com/openmls/openmls . Documentation indexed in this review showed OpenMLS 0.9.1 dated 2026-10-07 and support for several RFC 9420 cipher suites. Re-check releases before pinning.

### RFC 8785 — JSON Canonicalization Scheme (JCS)

- https://www.rfc-editor.org/rfc/rfc8785.html
- Canonical serialization avoids hash/signature ambiguity between JSON representations. The v0.2 evidence manifest uses a deliberately restricted schema subset (Unicode property names sorted by UTF-16 code units, safe-range integers, no floats) whose encoding is deterministic for supported values. It does **not** claim to be a fully general JCS implementation. Before protocol-level cross-language signing or external evidence exchange, replace it with a maintained, standards-conformant implementation and run published RFC test vectors.

### RFC 9162 — Certificate Transparency v2

- https://www.rfc-editor.org/rfc/rfc9162.html
- Reuse the principles and Merkle inclusion/consistency proof pattern for an append-only evidence/audit transparency log. Do not call a local hash chain a transparency log: an independently witnessed append-only service and consistency checking are required to detect certain forms of equivocation.

### RFC 3161 — Time-Stamp Protocol

- https://www.rfc-editor.org/rfc/rfc3161.html
- A trusted timestamp token can assert that a digest existed by the TSA's asserted time under its policy. It does not prove when a message was authored, who typed it, or that the content is true. Preserve the token, TSA chain/policy, nonce, and validation result.

### C2PA Content Credentials

- Official specs landing: https://spec.c2pa.org/specifications/
- Latest page surfaced during this review: C2PA Specifications 2.4, https://spec.c2pa.org/specifications/specifications/2.4/index.html
- Use C2PA only as a media/content provenance adapter: signed claims about asset origin/history under its trust model. It does not prove the WhatsApp account that forwarded a file or the path between recipients. Validate claims, signing certificate trust, asset binding, revocation/time status, and tamper status.

### NIST post-quantum standards

- ML-KEM / FIPS 203: https://csrc.nist.gov/pubs/fips/203/final
- ML-DSA / FIPS 204: https://csrc.nist.gov/pubs/fips/204/final
- SLH-DSA / FIPS 205: https://csrc.nist.gov/pubs/fips/205/final
- NIST approval announcement: https://csrc.nist.gov/News/2024/postquantum-cryptography-fips-approved
- NIST SP 800-227 (published September 2025) provides recommendations for KEMs: https://csrc.nist.gov/pubs/sp/800/227/final
- Role distinction: ML-KEM is key establishment, ML-DSA and SLH-DSA are signature schemes. NIST has published errata planning notes for FIPS 203/204 in 2025/2026, so re-check errata before freezing parameters. Add only through explicit profiles and maintained libraries. Measure signature/key sizes and verification cost. Do not call a system quantum-secure because it has a PQC algorithm name in its configuration.

## 3. Indian policy / legal context to encode as configurable policy

### Official consolidated Rules

- MeitY consolidated PDF, updated as on 10 February 2026: https://www.meity.gov.in/static/uploads/2026/02/550681ab908f8afb135b0ad42816a1c9.pdf
- Rule 4(2) text surfaced in the PDF specifies a judicial order from a competent court or a Section 69 competent-authority order under the 2009 procedure/safeguards rules, supported with an electronic copy of the information. It contains offence-category/seriousness conditions, a less-intrusive-means provision, and wording limiting disclosure of message contents and information concerning the originator/other users.
- The adapter's legal policy is not the law itself. Maintain a versioned policy module reviewed by counsel; it must be possible to turn the integration off in a jurisdiction.

### Court status caveat

- The Delhi High Court order located in this research pass is dated 8 April 2026: https://indiankanoon.org/doc/162442452/ . It noted proposed amendments/consultation, requested written submissions, listed 14–15 July 2026, and continued interim orders.
- This research pass did not establish what occurred at or after those July hearings. Do not state that the challenge is resolved or that the April hearing schedule remains current. Check the court docket/orders before any legal reliance.

### Internet Society impact report

- https://www.internetsociety.org/resources/doc/2024/traceability-in-end-to-end-encrypted-environments/
- Useful technical and socio-economic analysis of India's traceability debate, including risks of weakening E2EE, identity and metadata leakage, and failure modes of naive proposals.
- It is a policy analysis rather than a binding legal source. Treat it as input to threat modelling, not as legal authority.

## 4. Forensics research relevant to evidence adapters

### Web and UWP artifacts (2025)

- Kim, Hur, Kang & Kim, *Analyzing the Web and UWP versions of WhatsApp for digital forensics*, Forensic Science International: Digital Investigation, March 2025.
- https://www.sciencedirect.com/science/article/pii/S2666281724001884
- The paper analyzes specific Web and Windows app versions and reports that some needed data was stored locally. Artifact locations and version details can change quickly; treat it as a citation for the need to document tool/app versions, not a universal recipe.

### Mobile encrypted database research (2025)

- Prabowo, Mohsen & Selamat, *WhatsApp Mobile Applications in the Lens of Digital Forensics: Deciphering the Msgstore.db.crypt14 File*, published 14 October 2025.
- https://doi.org/10.13052/jcsm2245-1439.1443
- Relevant to evidence classification, versioned parsers, documented acquisition, keys/data provenance, and the consequences of device/number change. WhatsApp Traceability Research Lab should not use publications like this to bypass device/account protections; actual acquisition/decryption remains restricted to lawfully authorized examiner workflows and documented tools.

## 5. Competitive / prior art conclusion

This is not an empty field. The 2019 codebase already implements path/tree traceback in Rust; subsequent papers improve source-only disclosure, long-hop tracking, and abuse resistance. The strongest differentiated project is a tested **research framework plus evidence/provenance/authorization layer**, not a claim to have discovered source tracing.

Before any release that claims “implements paper X,” maintain a `papers/` record with version/commit, licenses, exact claim-to-code mapping, known deviations, reproduction results, and external review. Do not copy research code into the project until its license is verified.

## 6. Bibliography / canonical links

1. Tyagi, N., Miers, I., Ristenpart, T. (2019). *Traceback for End-to-End Encrypted Messaging*. https://eprint.iacr.org/2019/981
2. Tyagi et al. reference code. https://github.com/nirvantyagi/tracing
3. Peale, C., Eskandarian, S., Boneh, D. (2021). *Secure Complaint-Enabled Source-Tracking for Encrypted Messaging*. https://doi.org/10.1145/3460120.3484539
4. Branco, P., Green, M., Hegde, A., Jain, A., Kaptchuk, G. (2025). *How to Trace Viral Content in End-to-End Encrypted Messaging*. https://eprint.iacr.org/2025/1052
5. Wang et al. (2026). *Abuse Resistant Traceability with Minimal Trust for Encrypted Messaging Systems*. https://www.ndss-symposium.org/ndss-paper/abuse-resistant-traceability-with-minimal-trust-for-encrypted-messaging-systems/
6. IETF RFC 9420. https://www.rfc-editor.org/rfc/rfc9420.html
7. IETF RFC 8785. https://www.rfc-editor.org/rfc/rfc8785.html
8. IETF RFC 9162. https://www.rfc-editor.org/rfc/rfc9162.html
9. IETF RFC 3161. https://www.rfc-editor.org/rfc/rfc3161.html
10. C2PA specifications. https://spec.c2pa.org/specifications/
11. NIST FIPS 203. https://csrc.nist.gov/pubs/fips/203/final
12. NIST FIPS 204. https://csrc.nist.gov/pubs/fips/204/final
13. NIST FIPS 205. https://csrc.nist.gov/pubs/fips/205/final
14. MeitY consolidated IT Rules (as updated 2026-02-10). https://www.meity.gov.in/static/uploads/2026/02/550681ab908f8afb135b0ad42816a1c9.pdf
15. Internet Society (2024). *Traceability in End-to-End Encrypted Environments*. https://www.internetsociety.org/resources/doc/2024/traceability-in-end-to-end-encrypted-environments/
16. Kim et al. (2025). *Analyzing the Web and UWP versions of WhatsApp for digital forensics*. https://doi.org/10.1016/j.fsidi.2024.301861
17. Prabowo et al. (2025). *WhatsApp Mobile Applications ... Msgstore.db.crypt14*. https://doi.org/10.13052/jcsm2245-1439.1443
18. NIST SP 800-227 (2025). *Recommendations for Key-Encapsulation Mechanisms*. https://csrc.nist.gov/pubs/sp/800/227/final
