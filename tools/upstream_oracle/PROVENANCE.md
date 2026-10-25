# Upstream Reference Oracle Provenance

**Upstream Repository:** `https://github.com/nirvantyagi/tracing`  
**Upstream Commit SHA:** `24644f73fae82c1f6f4d7daea4f24638ecfd060b` (immutable 40-character Git reference on `master`)  
**Upstream Research Reference:** Nirvan Tyagi, Ian Miers, Thomas Ristenpart. *Traceback for End-to-End Encrypted Messaging*. ACM CCS 2019 / IACR Cryptology ePrint Archive Report 2019/981.  
**Upstream License:** Unspecified / Academic Research Prototype. In accordance with open source license hygiene, zero upstream code is vendored into this repository. All reference vectors are generated via an isolated external checkout and reviewable patch.

---

## Toolchain & Build Environment

Reference vectors were generated in an isolated environment using the following verified toolchain:

- **Host OS:** Windows 11 (AMD64)
- **Rust Toolchain:** `rustc 1.101.0-nightly (12433c307 2026-10-24)` / `cargo 1.101.0-nightly (cad07cf8e 2026-10-23)`
- **Host Target:** `x86_64-pc-windows-msvc`

---

## Patch Architecture (`0001-expose-oracle-vectors.patch`)

The upstream repository does not declare a public API for its internal primitives (`hash`, `prf`, `crprf`, `encipher`, `decipher`), and its message tag struct fields are crate-private. Furthermore, line 1 of `tracing/src/lib.rs` declares `#![feature(test)]`, which mandates a nightly compiler.

To extract deterministic reference vectors without reimplementing the algorithms or altering the upstream logic, `0001-expose-oracle-vectors.patch` applies the following surgical changes:
1. Adds `pub` visibility to `hash`, `prf`, `crprf`, `encipher`, and `decipher` in `tracing/src/lib.rs`.
2. Adds `pub` visibility to the struct fields of `TraceMetadata`, `SenderTraceTag`, and `RecTraceTag` in `tracing/src/path.rs`.
3. Adds `tracing/examples/oracle_vectors.rs`, a standalone binary invoking the actual upstream functions with fixed cryptographic seeds and emitting structured JSON.

---

## Verification & Output Artifacts

The generated Known-Answer Test (KAT) vectors are committed to:
- [`tests/data/oracle/tyagi2019_rust_oracle_vectors.json`](file:///C:/Users/amith/.gemini/antigravity/scratch/whatsapp-traceability-research/tests/data/oracle/tyagi2019_rust_oracle_vectors.json)

Differential test assertions comparing the oracle against Python are executed in:
- [`tests/test_upstream_differential.py`](file:///C:/Users/amith/.gemini/antigravity/scratch/whatsapp-traceability-research/tests/test_upstream_differential.py)
