# WhatsApp Traceability Research Lab Master Technical Specification

**Document status:** v0.2 implementation specification; underlying tracing protocol adapters remain unimplemented  
**Review date:** 2026-10-23  
**Audience:** cryptographers, privacy/security engineers, digital-forensics practitioners, researchers, and maintainers  
**Normative status:** design direction, not a production protocol specification

## 1. Executive objective

WhatsApp Traceability Research Lab is a reproducible, open-source environment for studying how a messaging system could identify the first originator of a reported message while limiting the exposure of unrelated users and communications. It also supplies a separate evidence-integrity and authorized-artifact analysis layer.

The project has two related but distinct tracks:

1. **Prospective protocol track:** protocols designed into a messaging client/server from the beginning, where origin/forwarding provenance is generated and cryptographically protected at send/forward time.
2. **Retrospective evidence track:** analysis of evidence that an investigator or device owner has already lawfully acquired, such as exports, supplied databases, forensic reports, or other documented artifacts. This track reports what the supplied evidence supports; it cannot manufacture absent historical events.

WhatsApp Traceability Research Lab is not a WhatsApp plugin and has no access to WhatsApp's internal systems. A phone number alone is not sufficient to fetch message history, backup status, deleted messages, keys, or a forwarding graph.

## 2. Goals

- Reproduce and compare major public protocol families for source tracing in E2EE messaging.
- Make the paper-to-code relationship explicit: version, threat model, assumptions, parameter choices, test vectors, and deviations are documented.
- Support a default **originator-only** result, with full path/tree disclosure as a distinct, more sensitive capability.
- Reduce the risk of abuse by separating authorization, complaint validation, policy evaluation, tracing, identity resolution, and report export.
- Produce tamper-evident, portable case bundles with signed manifests and clear evidence lineage.
- Expose uncertainty, missing data, clock skew, identity ambiguity, and protocol-version mismatches rather than hiding them.
- Benchmark privacy/utility/security tradeoffs and operational costs.
- Keep the framework useful for research even when a real platform never adopts it.

## 3. Non-goals

- Recovering any person's private history by entering a telephone number.
- Bypassing E2EE, defeating encrypted backup security, stealing credentials, or silently accessing another device/account.
- Claiming an actual message is true or false from its source trace alone.
- Treating a signed account credential as proof of a named person or of who physically held a device.
- Adding a secret mass-surveillance interface or an unaudited universal trace endpoint.
- Presenting a generic blockchain or a content hash as a substitute for cryptographic protocol design.
- Shipping experimental papers as production-ready without independent verification.
- Providing legal advice or determining that any particular request/order is lawful.

## 4. Core concepts and result labels

Every finding MUST include a claim type, supporting evidence references, verification method, scope, and limitations. The report vocabulary is:

- **Observed:** present in a supplied artifact, without cryptographic validation of its origin.
- **Integrity-verified:** the bytes match a signed/hash-committed artifact. This is not the same as truth.
- **Protocol-verified:** a specific supported protocol verifier validated a proof/signature under identified keys and version assumptions.
- **Provider-attested:** a provider-signed record states the field; this does not prove beyond its semantics that the underlying fact is true.
- **Externally time-stamped:** a trusted timestamp token validates for a digest, subject to TSA trust and policy.
- **Inferred:** calculated from stated evidence using a disclosed rule; include alternatives and confidence limitations.
- **Unverified / unknown:** evidence is absent, contradictory, malformed, or outside the adapter's documented coverage.
- **Synthetic:** generated for tests/demo and categorically not real-world evidence.

Never report “person X originated this” solely because an event contains a phone number. Safer wording: “the protocol credential mapped by provider assertion Y to account identifier Z is the earliest valid origin event in this trace.” A separate identity-resolution claim is required to map that account to a human.

## 5. Modes of operation

### 5.1 Originator-only mode (default)

Input: a reported message reference/content commitment, a valid authorization object, and protocol records/proofs. Output: the earliest origin credential allowed by the adapter and the policy, plus evidence, identity-binding status, and caveats. The output MUST NOT include all intermediate recipients unless the authorization scope and selected protocol explicitly permit it.

### 5.2 Path mode

Input: a report and protocol-specific trace state. Output: only the chain from the origin event to the reported copy. This can expose intermediate recipients and is therefore more sensitive than originator-only mode.

### 5.3 Tree mode

Output: all covered descendants/recipients known to the protocol, including branches. Tree mode should require explicit scope, stronger review, and a justification beyond convenience. It may still be incomplete if participation was partial, content was re-created, or some forwarding path used channels outside the instrumented service.

### 5.4 Retrospective evidence mode

Input: an investigator-supplied evidence bundle with acquisition metadata and authorization/custody records. Output: a structured evidence graph with explicit source types. This mode can correlate artifacts but MUST NOT pretend to supply cryptographic guarantees that the original platform did not provide.

## 6. System architecture

```text
                      +-------------------------------+
                      | Case / Authorization Service  |
                      | scope, purpose, expiry, audit |
                      +---------------+---------------+
                                      |
                                      v
+----------------+       +------------+-------------+
| Complaint /    |------>| Policy Gate / Quorum      |
| Report Package |       | independent trust domains |
+----------------+       +------------+-------------+
                                      |
                                      v
                           +----------+----------+
                           | Protocol Adapter API|
                           +----+-----+-----+----+
                                |     |     |
                   +------------+     |     +----------------+
                   v                  v                      v
          +----------------+ +-------------------+ +------------------+
          | 2019 traceback | | 2021 source track  | | HTS / 2026 labs   |
          +----------------+ +-------------------+ +------------------+
                                |
                                v
                     +----------+-----------+
                     | Minimal Result Filter|
                     | first origin by default|
                     +----------+-----------+
                                |
            +-------------------+--------------------+
            |                                        |
            v                                        v
 +-----------------------+              +---------------------------+
 | Authorized Identity   |              | Evidence / Case Bundle    |
 | Resolution (separate) |              | hashes, signatures, audit |
 +-----------------------+              +---------------------------+
```

The diagram is conceptual. v0.2 implements synthetic event-graph validation, signed evidence-manifest verification, an experimental multi-approver policy checker, and an offline Merkle proof lab. It does not implement the cited cryptographic source-tracing protocols or a production authorization server.

## 7. Protocol adapter interface

Each adapter MUST implement a common interface without pretending all constructions have the same guarantees:

- `adapter_id()`, `paper_reference()`, `implementation_version()`
- `supported_modes()`: origin-only/path/tree, where applicable
- `setup(config, participants, authorities)`
- `on_origin(message_context, sender_credential)`
- `on_forward(message_context, prior_reference, sender_credential)`
- `create_report(report_context, authorization_token, complaint_evidence)`
- `trace(report_context, policy_scope)`
- `verify_trace(trace_bundle)`
- `disclose(trace_bundle, scope)`
- `revoke_or_rotate_key(credential, effective_time)`
- `security_profile()` — adversary, assumptions, leakage, known attacks, paper deviations

Every call should return typed errors and a machine-readable assurance profile. Trace output should be a proof bundle, not merely a display name and a list of events.

### Adapter families

- `traceback-2019-path` and `traceback-2019-tree`: research reproduction. Treat separate modes because tree mode exposes a greater set of recipients and has distinct implementation complexity.
- `source-tracking-2021`: complaint-enabled source tracking; disclose source without revealing intermediate recipient identities where the scheme supports this property.
- `hts-2025`: model hop thresholds, anonymity threshold, path-length independence claims, and malicious-server security. Enforce valid threshold parameters; do not generalize beyond the paper's assumptions.
- `minimal-trust-2026`: model each trust participant as a distinct administrative/security domain, not multiple services controlled by the same operator. Track quorum decisions, collusion assumptions, and proof of each participant's contribution.
- `synthetic-graph-v0`: currently implemented demo adapter, explicitly marked `synthetic-only` and `not-a-cryptographic-traceback-protocol`.

## 8. Message and content identity

Do not use a single hash to claim that two arbitrary messages “are the same.” The model distinguishes:

- `content_commitment`: a protocol-specific commitment over a message payload/context as defined by that adapter.
- `exact_artifact_digest`: SHA-256 of exact supplied bytes, for evidence integrity only.
- `normalized_text_fingerprint`: optional research feature for text normalization; its normalization function/version MUST be recorded and collisions/false matches acknowledged.
- `media_candidate_fingerprint`: optional candidate-linking signal (e.g., perceptual hash) that can locate likely copies but is NOT proof of identical media or sender.
- `media_provenance`: C2PA Content Credentials or other signed claims, if present and valid; it describes media provenance, not the WhatsApp forwarding chain.

A screenshot, copy/paste, edit, recompression, cropping, transcription, or re-encoding can break exact-byte links or create a new object. An algorithm may provide a probabilistic lead, never silently upgrade it into cryptographically verified lineage.

## 9. Identity model

Represent separate entities:

- `AccountID`: protocol-level account credential or stable provider pseudonym.
- `DeviceID`: enrolled cryptographic device credential, with enrollment/revocation interval.
- `PhoneBinding`: a claim connecting an E.164 number to an AccountID during a stated validity interval, with issuer, signature, and verification status.
- `PersonIdentity`: an identity claim from an explicitly identified authority/evidence source, separated from protocol credential.
- `CredentialVersion`: key identifier, public key, key type, creation/expiry, revocation status, and rotation linkage.

A phone number can be ported, reassigned, SIM-swapped, shared across work/family workflows, or associated with multiple linked devices. Therefore, a number is a mutable locator, not an immutable principal. The system should avoid storing plaintext phone numbers unless necessary for a specific authorized case. Use scoped, case-local pseudonyms or encrypted fields where feasible; never use an unsalted public hash of low-entropy phone numbers as anonymization.

Identity-resolution output must name the issuer and validity window. If a provider response merely says “this number was associated with account A at time T,” report exactly that. Do not extrapolate to “person A typed the message.”

## 10. Time model

Each temporal claim must record:

- `claimed_time`: the supplied timestamp, if any.
- `clock_source`: device, application, provider, operating-system log, investigator annotation, or trusted timestamp authority.
- `observed_at`: time the evidence was collected, where known.
- `uncertainty_ms`: if genuinely supplied or calibrated; do not fabricate precision.
- `timezone_offset`: preserved at ingest, then normalized for ordering/display.
- `trusted_timestamp_token`: optional RFC 3161 token bound to a specific digest.
- `ordering_basis`: signed protocol sequence, append-only log index, provider sequence, trusted timestamp, or weaker local timestamp.

The report must not sort independent events into a single definitive timeline when their uncertainty intervals overlap. Device timestamps can be manipulated; timestamp tokens prove a trusted service saw a digest at/around a time under its policy, not necessarily when a message was created or sent.

## 11. Authorization and case controls

An authorization object should include:

- a unique request ID and issuing authority identity;
- jurisdiction and asserted legal basis / order reference;
- incident/case identifier;
- narrowly scoped message reference or commitment, target protocol/platform, and requested trace mode;
- prohibited scopes (other messages, other users, unrelated group branches);
- date/time validity interval and expiry;
- purpose and necessity/proportionality rationale;
- evidence copy/reference required by the applicable procedure;
- signatory identities and certificate validation status;
- approval policy and quorum attestations where used;
- review/appeal or revocation state where applicable;
- cryptographic hash of the complete request and audit event.

The technical engine should validate the structure and required signatures but MUST NOT declare the request legally valid in a general sense. Legal authority/competence is an external policy decision, documented as a verifiable assertion. Deny by default on missing scope, unknown signer, expired authorization, invalid signature, inconsistent case reference, or unsupported trace mode.

The 2026 consolidated Indian Rules text says Rule 4(2) is tied to specified orders/offences and contains a less-intrusive-means condition; it also limits disclosure of message contents and information about other users. A product implementation should obtain jurisdiction-specific legal review before turning any legal workflow into code.

## 12. Abuse-resistance design

The project must test and document at least these controls:

- **Independent trust domains:** separate entities must be administratively and cryptographically independent; two services under the same admin/account do not create meaningful distributed trust.
- **Quorum policy:** threshold approvals over request digest, case, target commitment, mode, expiry, and nonce; all approvers sign the same canonical request.
- **Replay prevention:** unique request IDs, nonces, short validity windows, case-bound request digest, and used-request registry.
- **Scope narrowing:** report output filtered to only fields required by the approved mode; tree disclosure separate.
- **Abuse reporting policy:** multi-reporter/complaint thresholds should be configurable and evaluated against Sybil/brigading risks; do not confuse many reports from controlled accounts with independent user evidence.
- **Anti-Sybil assumptions:** the design must say what makes a reporter “independent.” Phone-number diversity alone is weak; possible inputs include rate limits, account age signals, attested client state, and independent provider attestations, each with privacy/fairness implications.
- **Malicious server:** tests must cover dropping, reordering, replaying, fabricating, or forking records. Transparency consistency proofs can reveal some equivocation; they do not stop every denial-of-service or metadata attack.
- **Collusion:** threat model explicitly enumerates subsets of colluding tracing parties. Minimal-trust claims must cite the relevant formal proof and distinguish cross-organization separation from mere multi-server deployment.
- **Framing resistance:** verify origin/forward signatures, bind to content commitment and protocol context, key epoch, and message ID; test key compromise, credential substitution, and replay.
- **Abuse audit:** each trace attempt creates an immutable signed audit event including accepted/denied status, policy version, requesting principal, and scope. Keep audit metadata minimized and retention bounded.
- **Emergency pathway:** if ever studied, design it as separate, documented, time-bounded, reviewable, and independently logged; no silent bypass.

## 13. Cryptographic baseline and agility

For the initial evidence-manifest prototype:

- Ed25519 for signatures via the maintained `cryptography` library;
- SHA-256 for file digests and evidence-record hash links;
- a restricted deterministic JSON encoding for the current schema subset, with a future replacement requirement for a complete RFC 8785 implementation;
- separate signature and public-key files;
- no encryption of case evidence in v0.1, so never put private case data in generated public artifacts.

For future protocol research, all cryptographic algorithms must be adapter-configurable and identified in proof bundles. Prefer standardized, audited algorithms and libraries. NIST FIPS 203 ML-KEM is a KEM/key-establishment scheme; FIPS 204 ML-DSA and FIPS 205 SLH-DSA are signature standards. PQC integration needs explicit size/performance measurements, key lifecycle, certificate/encoding support, side-channel review, and a migration plan. Do not advertise “quantum-proof” based merely on adding one algorithm name.

Use RFC 3161 timestamps when an external TSA is desired; use an RFC 9162-style append-only transparency design for independently verifiable inclusion/consistency evidence. A local hash chain alone can be rewritten by an actor who can replace all records and signatures.

## 14. Evidence ingestion and chain of custody

### Initial supported inputs

- WhatsApp Traceability Research Lab's own JSON event schema (synthetic now; external import later).
- User-supplied case metadata and hash lists.
- A manifest of files already lawfully acquired and produced by an authorized examiner.

### Future adapters (must be separately reviewed)

- WhatsApp chat export files supplied by the account owner or authorized examiner.
- SQLite/JSON artifacts extracted through a lawful forensic workflow.
- Desktop/Web artifacts acquired from an authorized device, where a documented method applies to that application version.
- Provider-signed account/phone binding or message records if the provider supplies them under valid process.
- C2PA media credentials and other signed provenance formats.

The importer must record original file hash before parsing, source path/device/custodian where appropriate, acquisition time/method/tool version, operator, authorization/case number, write-blocking/acquisition details if applicable, parser version, and any transformations. Preserve original bytes read-only; store derived outputs separately; hash each derived output; never overwrite source evidence. Parser errors and unsupported versions are evidence results, not silently ignored warnings.

The first release will not implement account access, credential recovery, encrypted-backup bypass, mobile device exploitation, or extraction from remote numbers. Forensics must operate only on provided/authorized artifacts.

## 15. Report structure

A report bundle should contain:

- `case.json`: case metadata, scope, authorization references, jurisdiction policy identifier.
- `evidence/`: read-only originals or externally referenced evidence with digests; public demos use synthetic evidence only.
- `manifest.json`: canonical body, algorithm identifiers, record hashes, evidence IDs, and limitations.
- `manifest.sig`: detached signature.
- `signing-public-key.pem` or public key/certificate reference.
- `authorization/`: signed authorization objects and validation outcomes, where safe/legal to retain.
- `trace.json`: machine-readable graph/proof output.
- `report.pdf` or `report.md`: human-readable narrative, caveats, and provenance table.
- `audit.jsonl`: append-only signed case actions.
- optional `timestamps/` and `transparency/` proof material.

Redact only through a documented view/derivative. The original evidence remains preserved; each redacted output gets its own hash and a relation to the source.

## 16. Required security properties

Each protocol adapter must state which properties are achieved and which are not:

- correctness/completeness under stated availability assumptions;
- unforgeability of origin/forward evidence;
- privacy of unreported messages;
- minimal disclosure for origin-only mode;
- deniability properties, if compatible with other goals;
- accountability / misuse detection for tracing requests;
- resistance to malicious-server manipulation;
- resistance under stated collusion thresholds;
- replay resistance and freshness;
- credential revocation and rotation semantics;
- robust handling of duplicate/colliding content commitments;
- safe handling of partial traces and unavailable participants;
- forward/backward security where relevant to the construction;
- metadata leakage description (sender/recipient identity, timing, group membership, forwarding graph, message length, report behavior).

Do not transfer a property from one paper to another adapter or claim formal proof based only on passing unit tests.

## 17. Evaluation and benchmarks

Measure each adapter separately. Report distributions, not one “fast” data point:

- message overhead in bytes and percentage;
- per-message client CPU and memory;
- server storage per message and per forward;
- report proof size, trace latency, and verifier CPU;
- latency as path length increases and as forwarding trees branch;
- performance for origin-only versus path/tree modes;
- cost of key rotation, revocation, quorum approvals, and log proofs;
- false attribution under content transformations and credential compromise;
- metadata leakage under each adversary/view;
- success under dropped, duplicated, reordered, or maliciously edited records;
- privacy exposure when participants/authorities collude;
- reproducibility across operating systems and compiler/library versions.

Synthetic parameters should include path length 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024; branching factors 1, 2, 4, 8; and variable report/anonymity thresholds for HTS. These are benchmark axes, not a claim that any specific scheme scales to each point.

## 18. Advanced but carefully scoped extensions

- **Post-quantum agility:** profile-level algorithm negotiation and crypto-agility tests; do not silently change algorithms.
- **C2PA 2.4 media provenance:** parse and validate media Content Credentials when available. It proves signed claims about media history under its own trust model, not message-origin or forwarding path.
- **MLS/RFC 9420 test messenger:** an optional group-E2EE lab harness may use a maintained implementation such as OpenMLS. MLS is not WhatsApp's protocol and is not itself a traceback system.
- **Key transparency:** publish/account-key changes to a transparency log, use consistency/inclusion verification, and test log equivocation. This helps notice identity-key substitution but does not itself establish that a phone number belongs to a human.
- **Zero-knowledge proofs:** explore only if they demonstrably reduce disclosure, for example proving a credential satisfied a policy without revealing unrelated fields. Each ZK proposal must provide circuit/statement definition, setup assumptions, prover cost, verifier cost, and soundness/privacy review; avoid adding ZK for marketing.
- **Secure hardware/attestation:** optional trust signal, not a universal requirement. Document supply-chain and platform trust assumptions, and do not treat an attestation as proof of human intent.
- **AI-assisted forensic triage:** if added later, use only as a candidate generator with provenance references and calibrated uncertainty; AI must not create an evidentiary origin claim or determine guilt.

## 19. Definition of v0.1 done

- The synthetic graph includes a branch, and a report selects a path to a reported event.
- Malformed graphs fail closed.
- The evidence manifest hashes source and derived files and signs the manifest.
- Verification detects changed bytes, changed records, invalid signatures, path traversal, and missing files.
- Unit tests cover at least all cases in `docs/TEST_PLAN.md` that apply to implemented functions.
- All reports carry synthetic-only disclaimers.
- No WhatsApp access or unsupported private-history claims are made.
- Research and legal assumptions are documented and versioned.

## 20. Open decisions before protocol implementation

- Which paper adapter is first for independent reproduction? Recommended: reproduce the 2019 path scheme, then compare the 2021 design; add HTS and 2026 minimal-trust designs as isolated labs.
- Whether to port protocol adapters to Rust immediately or use Python only for benchmark/orchestration. Recommended: Rust for protocol core after the reproduction scope is frozen; Python remains the data/scenario/analysis layer.
- Which independent organizations could serve as trust participants in a real deployment? A lab can simulate these parties but cannot validate real independence.
- What external trust anchor and legal governance are required in each intended jurisdiction?
- How to support data minimization, retention expiry, audit integrity, deletion duties, and challenge/appeal simultaneously?

These are research questions; mark decisions as provisional until tested or reviewed.


## 21. v0.2 implementation status snapshot

The implemented status is maintained in [`IMPLEMENTATION_STATUS.md`](IMPLEMENTATION_STATUS.md) and the change record in [`V0.2_RELEASE_NOTES.md`](V0.2_RELEASE_NOTES.md). v0.2 adds hardened evidence-manifest verification, a configurable request/approval policy lab, and an offline Merkle inclusion-proof lab. None of these additions implements the cryptographic tracing construction of the cited papers, establishes real-world legal authority, or provides a production transparency service.
