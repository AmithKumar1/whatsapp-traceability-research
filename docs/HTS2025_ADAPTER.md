# HTS 2025 Adapter: Threshold Model

## Research source

Pedro Branco, Matthew Green, Aditya Hegde, Abhishek Jain, and Gabriel Kaptchuk, [*How to Trace Viral Content in End-to-End Encrypted Messaging*](https://eprint.iacr.org/2025/1052), IACR Cryptology ePrint Archive, paper 2025/1052.

The paper introduces Hop Tracking Signatures (HTS) to support tracing message originators after long forwarding paths while preserving anonymity for other participants, and analyzes security against malicious servers. Its abstract reports a negative result when tracing and anonymity thresholds differ by exactly one hop, and a positive succinctness result with a larger gap under strong assumptions.

## What the adapter does

`src/opentrace/protocols/hts2025.py` models only the threshold relationship:

- `anonymity_threshold_hops`: threshold parameter in the toy scenario.
- `trace_threshold_hops`: source recovery becomes eligible at or beyond this number of hops.
- `threshold_gap_hops`: calculated as trace threshold minus anonymity threshold.
- A gap of one labels the paper's negative succinctness result; a gap of at least two labels the paper's positive result as *possible under its assumptions*.
- No intermediate forwarders are disclosed in the model output.

The `didactic_payload_size_proxy_bytes` field deliberately illustrates constant-versus-growing behavior. It is **not** a predicted byte size for an HTS signature and must not be used to estimate a real deployment's bandwidth, storage, or cryptographic cost.

## Run it

```bash
opentrace hts2025-demo --hops 8 --anonymity-threshold-hops 2 --trace-threshold-hops 4

opentrace compare \
  --hops 8 \
  --hts-anonymity-threshold-hops 2 \
  --hts-trace-threshold-hops 4 \
  --out artifacts/protocol-comparison.json
```

## What is not implemented

This is **not** the paper's HTS algorithm. It creates no HTS signature, cryptographic tag, zero-knowledge proof, or verification transcript; it has no malicious-server game, formal reduction, streaming algorithm, or interoperability vector. It is marked `reference_status: synthetic` and `interoperable_with_reference: false`.

## Required work before claiming reproduction

1. Translate the paper's full syntax and security games into a protocol specification.
2. Identify an official/reference implementation and pin a commit, if one is available.
3. Implement with reviewed cryptographic primitives rather than the toy proxy.
4. Create fixed test vectors and negative/tamper cases.
5. Model malicious-server behavior and prove that disclosed identities satisfy the paper's exact threshold semantics.
6. Differential-test against the reference implementation and obtain independent cryptographic review.
