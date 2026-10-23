# Legal, Ethical, and Operational Scope

## Product boundary

WhatsApp Traceability Research Lab is research tooling. It must not claim to be an official government tracing system, a WhatsApp-integrated service, or a method to fetch another person's history by number. Do not use the project to conduct covert surveillance, access an account without authorization, bypass encrypted backup or device controls, or publish private conversations.

## Legal-policy model

Legal authority varies by jurisdiction, and a technically valid request is not necessarily legally valid. The software can validate signatures, expiry, required fields, scope, quorum, and policy parameters; an authorized legal reviewer must validate legal competence, applicability, necessity, proportionality, and procedure.

A jurisdiction profile should be versioned by source/date and support disabled-by-default behavior when a requirement is unknown. Do not hardcode a broad universal “government access” mode.

## India-specific research notes (not legal advice)

The official MeitY consolidated IT Rules PDF located for this specification is updated through 10 February 2026. Rule 4(2) addresses first-originator identification by a judicial order or an order under Section 69 by the competent authority under the cited 2009 procedural safeguards. The provision includes restrictions tied to offence categories/seriousness, a condition involving less-intrusive means, and limits on required disclosure. Read the exact current text and consult counsel before implementing a live process:

https://www.meity.gov.in/static/uploads/2026/02/550681ab908f8afb135b0ad42816a1c9.pdf

The Delhi High Court order located during this research dated 8 April 2026 recorded proposed amendments under consultation, directions for written submissions, a hearing listing for 14–15 July 2026, and continuation of interim orders:

https://indiankanoon.org/doc/162442452/

This review did not verify subsequent hearings/orders after July 2026. No claim is made about the current final status of the case. Before relying on it, review the official court docket and any later order.

## Data protection and minimization

- Default to local processing and synthetic test cases.
- Do not collect unrelated message contents as a side effect of trace.
- Keep the requested scope, trace mode, expiry and allowed fields machine-readable.
- Use case-local pseudonyms and avoid global phone-number search indexes.
- Limit plaintext phone-number exposure; do not use unsalted public phone-number hashes as pseudonymization.
- Encrypt sensitive live evidence in future deployments; exclude such data from telemetry and public CI.
- Define purpose limitation, retention, deletion, audit access, access review, and breach response before handling real cases.
- Where law requires preservation, use case-specific retention rules and immutable audit events, not indefinite general retention.

## Due process and error handling

- Provide a way to challenge mistaken account/number bindings and preserve exculpatory or contradictory evidence.
- Distinguish a trace link from criminal responsibility and intent.
- Record missing data and uncertainty.
- Require external review of protocol/security design and operational governance.
- Publish transparency information at an aggregate level only where lawful and where counts do not reveal individual cases.

## Research ethics

Use synthetic content or consented research participants. Document risks to vulnerable populations and threats of political misuse. A demo screenshot or model report must not include genuine phone numbers or content. Any testing against a production messaging service requires provider permission and an approved research plan.
