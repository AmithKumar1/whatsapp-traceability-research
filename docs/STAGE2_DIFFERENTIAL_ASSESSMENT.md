# Stage 2 — Reference Differential Testing

**Repository:** `AmithKumar1/whatsapp-traceability-research`  
**Basis:** handoff supplied on 2026-10-25; read-only inspection of `main`; upstream source review  
**Status:** assessment and acceptance plan only — this document does not claim a Stage 2 implementation, CI run, or PR.

## Recommendation

Proceed with **Stage 2 before declaring upstream interoperability**, and keep authorization replay prevention as a separate parallel workstream. The first Stage 2 task is to make the comparison target explicit: the current Python implementation is not byte-compatible with the upstream Rust prototype. A naive end-to-end differential test would conflate known algorithm/profile differences with bugs.

## Findings from the source review

The current Python module `src/opentrace/protocols/traceback2019_crypto.py` uses:

- 32-byte tracing keys and 32-byte message identifiers;
- HMAC-SHA-256 with a project-specific domain prefix for `mid`;
- HMAC-SHA-256 with a separate domain prefix for encryption-key derivation;
- AES-CTR with a zero 16-byte IV for predecessor-pointer encryption;
- the project's recipient identity checks and optional Ed25519 registry/signature extension.

The upstream Rust prototype at [`nirvantyagi/tracing`](https://github.com/nirvantyagi/tracing) uses a different primitive profile in `tracing/src/lib.rs` and `tracing/src/path.rs`:

- a 16-byte tracing key and a 16-byte predecessor pointer;
- HMAC-SHA3-256 directly over the message for `crprf` (the code does not add the Python implementation's domain prefix);
- AES-128 single-block encrypt/decrypt for predecessor pointers, rather than AES-CTR;
- Redis-backed lookup/storage for the path traceback server.

The paper describes the prototype's use of SHA-3, HMAC derived from SHA-3, AES-128, and Redis. The upstream README states that the library can compile on stable but the server requires Rust nightly; the tests require Redis and must run sequentially because they clear the database. See [upstream README](https://github.com/nirvantyagi/tracing), [upstream `lib.rs`](https://github.com/nirvantyagi/tracing/blob/master/tracing/src/lib.rs), and [upstream `path.rs`](https://github.com/nirvantyagi/tracing/blob/master/tracing/src/path.rs).

These are real compatibility differences, not automatically defects. They must be recorded as separate profiles and claims must distinguish “clean-room/paper-informed implementation” from “byte-compatible with the upstream prototype.” The existing Python tests demonstrate internal consistency and security invariants; on their own they do not establish interoperability with the Rust code.

## Stage 2 work breakdown

### 2.1 Pin and identify the oracle

- Pin the upstream repository to an immutable 40-character Git commit SHA. Do not use the floating `master` ref in repeatable CI.
- Record the upstream repository URL, source license, selected commit, `rustc -Vv`, `cargo -V`, Redis version, and OS/container image in a checked-in provenance record.
- Review the upstream license before copying code or storing modified source. Prefer downloading the original project at the pinned commit into an isolated worktree during CI, plus a small project-owned adapter patch, rather than silently vendoring the entire codebase.

### 2.2 Establish the upstream baseline separately

- Add an optional, isolated CI job/container for the upstream test suite.
- Start a pinned Redis service and run `cargo test -p tracing -- --test-threads=1` in the upstream checkout. Only run the server crate with the pinned nightly toolchain if it is needed by the chosen tests.
- Preserve the upstream test output and exit status as a distinct artifact. Do not count an upstream test pass as a Python test pass or as proof of cryptographic equivalence.
- Keep this job separate from the default cross-platform Python matrix until its older toolchain/dependency requirements are deterministic and maintainable.

### 2.3 Add deterministic, primitive-level oracle vectors

Add a tiny, project-owned Rust adapter/patch in the isolated oracle checkout that exposes deterministic reference vectors for the upstream functions. The fixture schema should identify the profile and operation, and include hex-encoded inputs and outputs. Start with:

1. `crprf(key, message)`;
2. AES-128 block encrypt/decrypt for a fixed 16-byte key and fixed 16-byte block;
3. `generate_tag` with a fixed tracing key, message, and predecessor pointer;
4. path tracing with fixed identities and a fixed sequence of keys, including wrong-message and recipient-ID mismatch cases where those semantics exist upstream.

The adapter must call the actual pinned upstream functions. It must not reimplement the same algorithms in a second Rust module and then label them reference outputs. If the adapter cannot expose a deterministic case without modifying upstream internals, keep that modification in a reviewable patch file and verify the patch applies exactly to the pinned source.

### 2.4 Compare profiles explicitly

Use one of two outcomes per case:

- **MATCH:** expected byte-for-byte equality within the same profile;
- **KNOWN_PROFILE_DIVERGENCE:** a documented algorithm/profile difference explains the output mismatch.

A known divergence must never be marked as a pass for interoperability. The first test suite should prove both that the Rust oracle fixture is stable and that the report labels the Python profile accurately. Add direct byte-equality assertions only after a Python compatibility profile intentionally implements the same upstream primitives and inputs.

### 2.5 Acceptance gates

Stage 2 is complete only when all of the following are true:

- The upstream source revision and toolchain are immutably pinned and documented.
- The isolated upstream test run is reproducible and produces a saved report.
- At least one fixed-key known-answer vector per primitive is generated by the pinned upstream functions and validated from Python.
- Every mismatch is classified, with no unexplained mismatch silently ignored.
- Public documentation separates upstream compatibility, paper-level claims, and Python-only security extensions.
- The regular Python CI, release audit, and existing historical manifest verification remain green.

## Explicit non-goals

- Do not rewrite the Python profile to mimic upstream primitives merely to make a differential test pass.
- Do not make the optional upstream job depend on unpinned `nightly`, an unpinned Redis image, or a moving upstream branch.
- Do not claim the paper's security theorems have been proven by these integration tests.
- Do not present successful Rust tests as proof that the Python extension's Ed25519 registry semantics exist upstream.

## Stage 2 evidence references

- Upstream README and test prerequisites: https://github.com/nirvantyagi/tracing
- Upstream path algorithm: https://github.com/nirvantyagi/tracing/blob/master/tracing/src/path.rs
- Upstream cryptographic primitives: https://github.com/nirvantyagi/tracing/blob/master/tracing/src/lib.rs
- Paper: Tyagi, Miers, Ristenpart, “Traceback for End-to-End Encrypted Messaging,” IACR ePrint 2019/981: https://eprint.iacr.org/2019/981.pdf
