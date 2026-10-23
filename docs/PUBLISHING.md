# Publishing and maintaining releases

Canonical repository: https://github.com/AmithKumar1/whatsapp-traceability-research

This project is published as an independent alpha-stage research framework. The repository and release workflow are deliberately separate from any WhatsApp/Meta service; they do not access live WhatsApp accounts or private messages.

## 1. Local preflight

From a clean checkout, use Python 3.11+ and install the pinned direct tooling:

```bash
python -m pip install -r requirements-dev.txt
python scripts/release_audit.py
python -m pytest -q
python -m compileall -q src
```

The audit checks package/citation version agreement, valid YAML and schemas, current examples, the signed synthetic evidence fixture, secret-marker scans, pinned GitHub Actions, the complete OS/Python test matrix, and the tag-only release job. It is a useful guardrail, not a security certification.

## 2. CI requirements

GitHub Actions runs nine test combinations: Ubuntu, Windows, and macOS on Python 3.11, 3.12, and 3.13, plus a dedicated packaging job. Matrix jobs exercise evidence creation and verification, authorization, Merkle proofs, all five synthetic research adapters, benchmark generation, protocol comparison, and JSON Schema validation. Packaging CI builds a wheel and source distribution, runs `twine check`, installs each in a clean virtual environment, checks dependencies with `pip check`, and tests the installed CLI.

The version-tag release job is gated on both the full test matrix and packaging job. Never create a version tag while either prerequisite is failing.

## 3. Repository settings

Enable secret scanning and push protection where available, Dependabot alerts and updates, private vulnerability reporting, and branch protection requiring successful CI on `main`. External GitHub Actions are pinned to full commit SHAs. Review upstream changes and update pins deliberately. Consider requiring code-owner review for `.github/workflows/`, `scripts/`, `src/opentrace/integrity.py`, and `src/opentrace/authorization.py` as the project gains maintainers.

## 4. Create a versioned release

Before a new release, update the version in `pyproject.toml`, `src/opentrace/__init__.py`, `CITATION.cff`, the changelog, current examples, and that release's notes. Set `date-released` in `CITATION.cff` to the actual intended release date only when preparing that release.

Run the strict checks locally:

```bash
python scripts/release_audit.py --require-release-date
python -m pytest -q
python scripts/build_release.py --final-release
```

After the main-branch CI passes, create and push the matching annotated tag:

```bash
git tag -a v0.5.2 -m "WhatsApp Traceability Research Lab v0.5.2"
git push origin v0.5.2
```

The tag starts the full CI matrix and packaging job again. Only if they both succeed does the release job rebuild the final wheel, source distribution, source ZIP, and SHA-256 checksum file, run `twine check`, and publish those assets to a GitHub Release with `docs/releases/v0.5.2.md` as the notes. Verify the GitHub Release assets and download checksums after the workflow completes.

All five traceability adapters are synthetic and non-interoperable. The project is not integrated with WhatsApp or another live messaging service and makes no claim that a phone number alone can reveal private message history.
