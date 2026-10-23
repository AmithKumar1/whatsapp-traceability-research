# Publishing and maintaining releases

Canonical repository: https://github.com/AmithKumar1/whatsapp-traceability-research

This project is published as an alpha research framework. Source publication and a versioned software release are separate milestones: the first source commit may exist before the first tagged release. Do not describe hosted CI as passing until the GitHub Actions checks for the relevant commit have completed successfully.

## 1. Local preflight

From a clean checkout, use Python 3.11+ and install the pinned direct tooling:

```bash
python -m pip install -r requirements-dev.txt
python scripts/release_audit.py
python -m pytest -q
python -m compileall -q src
```

The release audit checks package/citation version agreement, valid YAML and schemas, current examples, the signed synthetic evidence fixture, secret-marker scans, pinned GitHub Actions, and publication guardrails. It is a useful guardrail, not a security certification.

## 2. CI requirements

The GitHub Actions workflow runs nine test combinations: Ubuntu, Windows, and macOS on Python 3.11, 3.12, and 3.13, plus a dedicated packaging job. Each matrix job exercises evidence creation and verification, authorization, Merkle proofs, each of the five synthetic research adapters, benchmark generation, protocol comparison, and JSON Schema validation. Packaging CI builds the wheel and source distribution, runs `twine check`, installs each in a clean virtual environment, checks dependencies with `pip check`, then exercises the installed CLI and verifies a generated report.

Do not tag a release until all hosted CI jobs pass. If any job fails, fix the issue, push the fix, and rerun the workflow. Local results do not substitute for hosted CI.

## 3. Repository settings

Enable secret scanning and push protection where available, Dependabot alerts and updates, private vulnerability reporting, and branch protection requiring successful CI on `main`. External GitHub Actions are pinned to full commit SHAs. Review upstream changes and update those pins deliberately. Consider requiring code-owner review for `.github/workflows/`, `scripts/`, `src/opentrace/integrity.py`, and `src/opentrace/authorization.py` as the project gains maintainers.

## 4. Prepare a final release

After hosted CI passes, set `date-released` in `CITATION.cff` to the actual release date and run:

```bash
python scripts/release_audit.py --require-release-date
python scripts/build_release.py --final-release
```

The final builder requires a canonical repository URL and valid release date, builds the source distribution and wheel using the pinned build tooling, runs `twine check`, creates a source ZIP, and writes SHA-256 checksums. Verify that the checksums match the artifacts before upload. Do not upload candidate artifacts as a tagged release.

Tag and push only after final metadata, CI results, ownership, license, and research limitations are reviewed:

```bash
git tag -a v0.5.2 -m "WhatsApp Traceability Research Lab v0.5.2"
git push origin v0.5.2
```

Create the GitHub Release and attach the source ZIP, Python source distribution, wheel, and matching checksum file. Use the corresponding `CHANGELOG.md` entry for the release notes. Preserve the limitations statement: all five adapters are synthetic, none is interoperable, and the project is not integrated with WhatsApp or other live messaging services.
