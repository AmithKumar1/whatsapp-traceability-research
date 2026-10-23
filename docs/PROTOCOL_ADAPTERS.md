# Protocol Adapter Design Notes

## Why adapters must stay separate

The papers in this repository address different goals and use different trust assumptions. Combining selected components from each into a single unproven construction can destroy the properties the paper was designed to establish. WhatsApp Traceability Research Lab therefore normalizes only the *research harness interface*; cryptographic protocol details remain adapter-specific.

## Comparative matrix

| Dimension | 2019 path/tree traceback | 2021 complaint-enabled source tracking | 2025 HTS | 2026 minimal-trust scheme |
|---|---|---|---|---|
| Main question | Reveal path or forwarding tree for reported copy | Reveal source through complaint-enabled process with privacy for intermediate recipients | Trace after long/viral path while retaining anonymity for others | Limit abuse by distributing trust and minimizing disclosure |
| Output mode | Path and tree variants | Source-tracking variants; confirm exact output per construction | Originator tracing tied to hop thresholds | Source tracing under its distributed-trust syntax |
| Key design issue | Encrypted links/pointers and incremental trace structures | Complaint integrity and source-only disclosure | Threshold gap between traceability and anonymity; succinctness | Real separation/independence of trust participants and collusion model |
| Adversary focus | Per paper's traceability/privacy games | Per paper's complaint/source-tracking games | Explicit malicious-server security | Collusion and abuse of tracing authority |
| First WhatsApp Traceability Research Lab task | Reproduce baseline tests and benchmarks | Extract formal functionality and replicate guarantees | Build parameter/model harness; implement only against paper spec | Model distinct entities and collusion cases; reproduce paper implementation |
| Deployment maturity in this project | Synthetic model only | Synthetic source-only model; crypto reproduction pending | Synthetic threshold model; crypto reproduction pending | Synthetic policy-gate model; crypto reproduction pending |

The matrix is an orientation aid, not a formal security comparison. Before coding each adapter, maintainers must read the full paper, define the exact syntax, extract assumptions, and reproduce reported results.

## Adapter metadata contract

Every adapter should publish a signed/checked-in `adapter.toml` or machine-readable record with fields similar to:

```toml
adapter_id = "example-adapter"
status = "research-only" # planned | in_progress | replicated | independently_reviewed | production_considered
paper_url = "https://example.invalid/paper"
paper_version = "exact version/date"
source_commit = "full commit hash or null"
implementation_language = "Rust"
supported_modes = ["origin-only"]
trust_model = "summary plus link to threat model"
known_deviations = []
benchmark_status = "not-run"
```

The placeholder above is a schema illustration only and must not be copied as an actual adapter record. The project should avoid `production` status until a separate review is completed. In v0.5, HTS and minimal-trust have toy models only; they are not faithful reproductions.

## Required per-adapter specification

1. Define parties and keys: sender, recipient, server(s), reporters, tracing participants, identity provider, verifier.
2. Specify messages at origin and every forwarding operation; specify exactly which bytes/context are bound to each proof.
3. Specify complaint/report validity, report thresholds, evidence given by the complainant, and replay behavior.
4. Define what trace returns in each mode, including not-found, partial trace, duplicate content, and unavailable participant behavior.
5. Define privacy for unreported messages and metadata leakage even when content remains encrypted.
6. Define server malice/collusion, client/key compromise, Sybil, replay, and denial-of-service assumptions.
7. Specify key rotation, revocation, account migration, device loss, old proofs, and provider/identity-binding semantics.
8. Translate security definitions into executable tests or proof-assistant artifacts where feasible.
9. Reproduce paper benchmarks, including environment, parameters, and deviations.
10. Make output verifiable offline and describe what the verifier must trust.

## Origin-only vs full tree

Do not expose one `trace()` function that silently returns the maximum possible disclosure. Use a typed request:

```text
TraceRequest {
  case_id,
  authorization_digest,
  target_content_commitment,
  mode: ORIGIN_ONLY | PATH | TREE,
  expiry,
  nonce,
  requested_fields,
}
```

The policy gate checks the mode and fields before calling the adapter. The adapter should return the smallest proof/output capable of satisfying the approved mode. A later renderer must not add hidden recipient data that was not required by the approved request.

## HTS parameter validation

The 2025 HTS work makes hop thresholds a central design parameter. The adapter must use the exact paper terminology and semantics; do not assume threshold inequalities from memory. It should reject unsupported/insecure combinations instead of coercing them to the nearest legal values. Tests must include:

- every valid parameter relation from the paper;
- the one-hop threshold-gap boundary discussed in its negative result;
- larger-gap configurations supporting the paper's positive result;
- short paths, exactly-at-threshold paths, threshold-plus-one, and paths far beyond threshold;
- malicious-server attempts to alter hop labels, truncate or fork a chain, and replay a proof for another message.

A successful benchmark is not evidence of the theorem; code and theorem assumptions must agree.

## Minimal-trust model

The authority graph must track organizational control, not just server endpoints. The test model should distinguish:

- two machines controlled by one organization;
- two cloud regions controlled by one organization;
- two independently administered organizations;
- authorities that share a key-management system;
- compromised and colluding authority subsets.

For each model, enumerate which coalition can authorize trace, which coalition learns which secrets, and whether an honest participant can refuse a malicious request. Only claim the “one honest participant” property when the exact published construction, its assumptions, and its proof support the claim.

## Handling protocol evolution

Protocol output must include `adapter_id`, adapter version, protocol version, key epoch, public-key identifiers, proof format, and algorithm profile. Verifiers should fail closed on unknown required fields or algorithms. Version migration must include explicit tests that old proofs remain verifiable under documented trust/revocation rules without accepting downgraded security profiles.
