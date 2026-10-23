# Architecture Decision Records

## ADR-001 — Keep prospective tracing separate from retrospective forensics

**Status:** Accepted.  
**Decision:** Separate protocol-time provenance construction from post-acquisition evidence analysis.  
**Reason:** A protocol can record/cryptographically protect provenance at send/forward time; a forensic parser can only analyze the evidence actually available. Mixing them would invite false promises of retroactive traceability.

## ADR-002 — First-originator-only is default disclosure

**Status:** Accepted.  
**Decision:** Origin-only disclosure by default; path/tree is a separate typed, scope-bound request.  
**Reason:** Tree/path traces reveal additional recipients. Minimizing disclosure protects unrelated users and better matches a request scoped to identifying the first originator.

## ADR-003 — Synthetic demo first

**Status:** Accepted.  
**Decision:** v0.1 ships a synthetic branching graph and evidence bundle only.  
**Reason:** It validates architecture, report semantics and case integrity without implying WhatsApp integration or requiring real private data.

## ADR-004 — Cryptographic algorithms are adapter-specific

**Status:** Accepted.  
**Decision:** Never force one generic signature scheme onto every research construction.  
**Reason:** A scheme's formal security may depend on its specific construction, assumptions, linkability, or secret-sharing model. Use a common interface but preserve protocol-specific cryptographic syntax.

## ADR-005 — Ed25519 + SHA-256 for local manifest prototype

**Status:** Accepted for v0.1 only.  
**Decision:** Use maintained Ed25519 and SHA-256 primitives for local file integrity manifests.  
**Reason:** Compact, familiar and interoperable. This doesn't choose the primitives for the eventual traceback protocol and doesn't provide post-quantum security.

## ADR-006 — No self-built general JCS implementation claim

**Status:** Accepted.  
**Decision:** Current canonicalization supports only the project's restricted JSON subset; full RFC 8785 conformance is a Phase 1 gate.  
**Reason:** Canonicalization bugs invalidate signatures. The current restrictions provide deterministic local test bytes without pretending arbitrary JSON is covered.

## ADR-007 — Trust anchor is external

**Status:** Accepted.  
**Decision:** Verification can accept a separately trusted public key; bundled public key alone is self-signed and informational.  
**Reason:** Signature validity and signer identity are separate claims. High-assurance cases need externally authenticated keys/certificates and optionally independent timestamps/transparency proofs.

## ADR-008 — Blockchain is not an MVP requirement

**Status:** Accepted.  
**Decision:** Start with signed manifests and transparency-log interoperability; evaluate blockchain only if it solves a concrete independent-witness/distribution problem.  
**Reason:** Immutability rhetoric does not fix false input, bad identity binding, key compromise, governance, or privacy leaks.

## ADR-009 — Project name is provisional

**Status:** Provisional.  
**Decision:** Keep “WhatsApp Traceability Research Lab” as a working name for this scaffold; check repository/name/trademark collisions before public launch.  
**Reason:** “OpenTracing” is used in observability ecosystems, which could cause confusion even if the research domain differs.
