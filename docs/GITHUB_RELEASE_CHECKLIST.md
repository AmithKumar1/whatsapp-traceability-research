# First Public GitHub Release Checklist

The public repository exists at `https://github.com/AmithKumar1/whatsapp-traceability-research`. This checklist tracks readiness for the first tagged release; it is not evidence that the hosted CI matrix has passed.

## Repository identity

- [ ] Use the public project name WhatsApp Traceability Research Lab and repository slug `whatsapp-traceability-research`; clearly state that this is independent research and not affiliated with WhatsApp/Meta.
- [ ] Confirm the public repository owner and visibility; keep `CITATION.cff` and package metadata aligned with the canonical repository URL.
- [ ] Write a plain-language problem statement that describes research/evaluation, not a claim to access WhatsApp.
- [ ] Add the project license and ensure any future third-party source code is license-compatible before copying.

## Security and privacy

- [ ] Confirm the ZIP/repository contains no private keys, tokens, personal data, live case evidence, provider responses, or production conversation exports.
- [ ] Keep the bundled `examples/demo-case` synthetic; it contains a self-signed public key only, no private key.
- [ ] Verify `.gitignore` is working; public PEM keys/certificates may be needed in tests, private key files must not be committed.
- [ ] Enable secret scanning and push protection where available.
- [ ] Configure private vulnerability reporting/contact before encouraging security reports.
- [ ] Ensure issue and PR templates tell contributors not to upload private message data.
- [ ] Do not enable telemetry or upload evidence by default.

## Technical release

- [ ] Run `pytest` on supported Python versions; the included CI matrix is configured for Python 3.11–3.13 on Ubuntu, Windows, and macOS but still needs remote execution.
- [ ] Run schema validation and the included synthetic-bundle verification.
- [ ] Use `requirements-dev.txt` for pinned direct test/build tools; it is not a fully transitive lockfile. Review runtime/build dependency updates and Dependabot/security alerts.
- [ ] Check CI permissions; use read-only `contents` permissions unless the workflow needs more.
- [ ] Review pinned action commits on future upgrades; current checkout/setup-python refs are full-SHA pinned.
- [ ] Add `date-released` to `CITATION.cff` only after hosted CI passes; run `python scripts/release_audit.py --require-release-date` and `python scripts/build_release.py --final-release`.
- [ ] Tag `v0.5.2`; archive source and record SHA-256 checksum only after the repository identity/owner is confirmed and CI passes on the configured matrix.
- [ ] Keep the release notes explicit about what is and is not implemented.

## Scientific and legal claims

- [ ] Read the full source papers and confirm cited versions.
- [ ] Do not label any adapter “implemented” until it reproduces documented cases and known tests.
- [ ] Document all deviations from formal security models and paper parameters.
- [ ] Have any jurisdiction-specific live request workflow reviewed by qualified counsel.
- [ ] Do not make claims about the current outcome of the Indian court challenge without checking the latest official docket/order.
- [ ] Keep the synthetic demo prominently labelled as non-real and non-WhatsApp-integrated.

## Suggested repository description

> Open research framework for evaluating privacy-preserving source tracing in end-to-end encrypted messaging, with synthetic demos and verifiable evidence manifests.

## Suggested GitHub topics

`cryptography`, `end-to-end-encryption`, `privacy`, `digital-forensics`, `source-tracing`, `security-research`, `rust` (once the Rust protocol core exists), `reproducible-research`.
