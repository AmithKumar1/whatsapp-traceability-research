# Minimal-Trust 2026 Adapter: Policy-Gate Model

## Research source

Zhongming Wang et al., [*Abuse Resistant Traceability with Minimal Trust for Encrypted Messaging Systems*](https://www.ndss-symposium.org/ndss-paper/abuse-resistant-traceability-with-minimal-trust-for-encrypted-messaging-systems/), NDSS 2026, DOI [10.14722/ndss.2026.240456](https://doi.org/10.14722/ndss.2026.240456).

The paper distributes traceability across users/recipients, a platform, a regulator, and a moderator. At a high level, tracing depends on a sufficient number of reports, a regulator's private-blocklist decision, moderator review, and platform action. The paper formalizes security properties; this adapter does not reproduce those proofs or cryptographic mechanisms.

## What the adapter does

`src/opentrace/protocols/minimal_trust2026.py` exposes an auditable policy simulation with these gates:

1. `verified_distinct_reports >= required_reports`
2. `regulator_blocklist_match == true`
3. `moderator_approved == true`
4. `platform_release_authorized == true`

Source identity is returned by the toy decision only if all four gates pass. It also creates a **simulation-only** matrix illustrating how one designated honest role could block an innocent-message trace by enforcing its control. In the recipient row, the model assumes reports are verified and non-duplicated; no actual Sybil resistance, anonymous credential, or share verification is implemented.

## Run it

```bash
opentrace minimal-trust2026-demo --required-reports 3
opentrace compare --out artifacts/protocol-comparison.json
```

## Important limitations

- This is a policy-gate simulator, not the NDSS paper's cryptographic scheme.
- It does not implement secret sharing, anonymous credentials, Signal's private-group techniques, signed case approvals, regulator/moderator key management, or cryptographic recipient shares.
- Trust-domain independence is represented in explanatory output only. Different processes or accounts controlled by one organization are not independent real-world trust domains.
- The single-honest-role matrix is a model test, not proof that an implementation is abuse-resistant.
- No WhatsApp, Signal, provider API, or real user data is accessed.

## Required work before claiming reproduction

1. Specify the roles, their exact inputs/outputs, key lifecycle, and trust-domain independence requirements.
2. Translate each formal security property and adversary from the paper into executable models.
3. Implement the paper's reporting, blocklist, review, and tracing cryptography using reviewed primitives.
4. Test collusion subsets, replay, malformed reports, duplicate/Sybil reports, authorization mismatch, key revocation, and availability failures.
5. Differential-test against any reference implementation and obtain independent cryptographic review.
