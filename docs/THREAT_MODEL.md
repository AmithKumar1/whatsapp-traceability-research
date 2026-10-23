# Threat Model

## Assets to protect

- Contents and metadata of unreported messages.
- Identities of senders, recipients, reporters, and group members outside the authorized scope.
- Integrity of the reported message commitment, origin/forward proof, authorization, audit log, and exported case bundle.
- Confidentiality of private case files, signing keys, phone bindings, and examiner notes.
- Availability and reliability of tracing/verification in the presence of malformed data or partial outages.
- Correct interpretation: avoiding false attribution or presenting uncertain inferences as facts.

## Security principals

- `C`: complainant/reporting recipient.
- `S`: messaging service/server(s), which may be honest-but-curious or malicious.
- `U_i`: message originator and forwarding/receiving users.
- `A_j`: independent authorization/tracing participants.
- `P`: provider or trusted identity-assertion source.
- `E`: examiner/custodian who acquires evidence.
- `V`: independent verifier/report reviewer.
- `L`: transparency log and/or timestamp authority.

## Adversary classes

1. **Curious server:** tries to learn identities/graphs from ordinary, unreported messages.
2. **Malicious server:** fabricates, reorders, drops, forks, or selectively replays records; lies about log consistency.
3. **Abusive authority/requester:** requests tracing without sufficient authority, with overly broad scope, on an unreported/benign message, or for political/personal surveillance.
4. **Colluding participants:** combinations of servers, authorities, reporters, or clients try to bypass trace authorization or reconstruct more than the permitted data.
5. **Malicious reporter / Sybil attacker:** creates fake or coordinated reports, manipulates complaint thresholds, or reports altered content as original.
6. **Malicious or compromised client:** forges events, uses a stolen key, lies about local timestamps, replays old proof, or binds a different account/device.
7. **Credential/identity attacker:** substitutes a public key, abuses number reassignment, claims a phone number belongs to a specific person, or exploits key rotation/revocation gaps.
8. **Evidence manipulation attacker:** edits supplied files, changes metadata, swaps originals/derivatives, or modifies a report after signing.
9. **Insider:** accesses, exports, or retains more evidence than authorized.
10. **Availability attacker:** withholds proof shares, disables log/authority services, or creates computationally expensive input.

## Trust assumptions to make explicit

- Which keys are trusted and how trust roots are distributed.
- Whether the client code is honest and what happens after device compromise.
- Whether platform servers are honest, malicious, or colluding.
- How a report becomes eligible and how reporter independence is established.
- How authorization identities and legal documents are validated.
- Whether authorities are independent real-world entities or one administrative domain.
- Whether a timestamp authority/log is trusted, publicly witnessed, or can equivocate.
- What data the provider can see or store at message-send/forward time.

## Primary abuse cases and mitigations

| Abuse | Required mitigation / test |
|---|---|
| Trace arbitrary innocent messages | Narrow report eligibility; scope-bound authorization; quorum; rate limits; audit; red-team tests |
| Trace without a valid order | Fail-closed authorization policy; signer/certificate validation; expiry/revocation; deny-by-default |
| Use an origin-only order to obtain entire group tree | Typed disclosure scopes; tree mode separately approved; output filtering tests |
| Fake a forwarding chain | Cryptographic event/proof validation in real adapters; negative tests; distinguish synthetic graph edges from authenticated protocol edges |
| Attribute message to wrong human | Separate account credential, device, phone binding and person identity; temporal binding; report limitation |
| Reuse old approval for a new target | Nonce, case ID, content commitment, scope, mode, expiry in signed digest; replay registry |
| Colluding hosts bypass a central blocklist | Independent administration, threshold protocols, collusion analysis; never count replicated servers as independent parties |
| Claim trusted ordering from local device time | Explicit clock source and uncertainty; RFC 3161 token where needed; no forced chronology for overlapping intervals |
| Replace evidence and hashes | Signed manifest; externally anchored signer key; trusted timestamp/transparency witnesses for high assurance |
| Malicious manifest path reads outside case directory | Reject absolute/parent paths; resolve paths and enforce case-root containment |
| Content hash copied/reused as identity proof | Context-bound commitments; key/epoch binding; no mapping of digest to human identity |
| Leak evidence in telemetry/logs | Data minimization, local-first defaults, no content telemetry, configurable retention and redaction |

## Explicitly out of scope for v0.2

The v0.2 tool does not connect to messaging services, decrypt private backups, access a mobile device, perform account discovery, bypass permissions, or infer real users from phone numbers. Any later authorized artifact importer needs a separate review and must only read supplied files.

## Security claims: what the prototype can and cannot say

Can say: “The listed file bytes and sizes match the SHA-256 values in this manifest; the manifest signature verifies under this Ed25519 public key; the full payload inventory matches; record hash links are internally consistent.”

Cannot say: “The signer is a known authority” unless the key is externally trusted; “the evidence is true”; “the timestamp is trusted”; “the evidence was lawfully acquired”; “a real person authored the content”; or “this is a complete WhatsApp forwarding tree.”
