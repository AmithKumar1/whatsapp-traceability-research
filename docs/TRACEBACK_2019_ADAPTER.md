# 2019 Traceback Baseline Adapter

WhatsApp Traceability Research Lab v0.3 adds a **research-only synthetic path-traceback adapter** inspired by Tyagi, Miers & Ristenpart, *Traceback for End-to-End Encrypted Messaging* (CCS 2019).

The original reference repository is a Rust workspace containing path and tree implementations. Its README describes a `tracing` library plus a `tracing-server`, with tests and benchmarks backed by Redis. The WhatsApp Traceability Research Lab adapter is deliberately separate from that codebase and is **not wire-compatible** with it.

## What is implemented

- synthetic message metadata
- sender trace tag generation
- receiver tag verification
- server-side synthetic trace state
- identity-binding check during traceback
- wrong-message termination
- duplicate-address rejection
- path reconstruction over synthetic sender/receiver IDs
- benchmark points for 1/2/4/8/16/32 hops

## What is not claimed

- no WhatsApp integration
- no production messenger integration
- no interoperability with the Rust reference implementation
- no claim of reproducing the paper's performance numbers
- no real-user identity resolution
- no access to private messages or backups

## Why this is useful

This gives WhatsApp Traceability Research Lab a controlled baseline on which later adapters can be compared. Every protocol adapter will report at least:

| Metric | Meaning |
|---|---|
| trace correctness | Does the adapter recover the synthetic source/path under its stated model? |
| proof/tag size | Bytes introduced by traceability state |
| client cost | Local computation required per send/forward |
| server cost | Server-side processing/storage work |
| trace cost | Work required for a report/trace request |
| privacy leakage | Which participants or relationships become linkable |
| abuse surface | What an unauthorized or colluding party can learn |

## Reproduction gate

Before calling this a reproduction, WhatsApp Traceability Research Lab must execute the published Rust reference implementation and document matching test vectors, security assumptions, and benchmark methodology. Until then this adapter is only a clean-room research baseline.
