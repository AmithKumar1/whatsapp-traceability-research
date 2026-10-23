# Contributing

Thank you for contributing to WhatsApp Traceability Research Lab. The project's goal is to make source-tracing research auditable and to prevent overclaiming.

## Before opening a PR

1. Read `docs/MASTER_SPEC.md`, `docs/THREAT_MODEL.md`, and `docs/LEGAL_AND_ETHICAL_SCOPE.md`.
2. Keep demos synthetic; never commit real conversations, phone numbers, private keys, or extracted device evidence.
3. Add tests for normal, malformed, adversarial, and boundary cases.
4. State the threat model and guarantees that a change provides—and explicitly state what it does not provide.
5. Do not claim a published construction is reproduced unless the paper's security model, parameter choices, algorithms, and test vectors are documented.
6. Do not add a new cryptographic primitive if an audited library and standard format can be reused.
7. Run `pytest` before submitting changes.

## Protocol adapter proposals

A protocol adapter proposal must include: paper/version, functionality, adversary model, trust assumptions, formal security properties, key lifecycle, metadata leakage, abuse cases, interoperability format, benchmarks, independent implementation review, and limitations. The adapter should be disabled by default until the tests pass.

## Contribution areas

- Research replication and literature review
- Formal models and security proofs
- Schemas and evidence provenance
- Adversarial/negative testing
- Privacy-preserving reporting
- Reproducible benchmarks
- Accessibility, documentation, and translations
