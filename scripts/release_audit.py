#!/usr/bin/env python3
"""Local pre-publication audit for WhatsApp Traceability Research Lab source bundles.

This is a guardrail, not a security certification or a substitute for hosted CI.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from opentrace import __version__  # noqa: E402
from opentrace.integrity import verify_case  # noqa: E402

try:
    import jsonschema
    import yaml
except ImportError as exc:  # pragma: no cover - CLI diagnostic
    raise SystemExit("Install the pinned development tools first: python -m pip install -r requirements-dev.txt") from exc

PRIVATE_KEY_MARKER = re.compile(
    r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----",
    re.IGNORECASE,
)
TOKEN_PATTERNS = (
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{30,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"),
)
SKIP_DIRS = {".git", ".pytest_cache", "__pycache__", ".venv", "venv", "build", "dist", "htmlcov", "artifacts"}


def fail(message: str) -> None:
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def audit(allow_missing_repository_code: bool = False, require_release_date: bool = False) -> int:
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    project = pyproject["project"]
    version = project["version"]
    if version != __version__:
        fail(f"pyproject version {version!r} does not match imported package version {__version__!r}")

    citation = (ROOT / "CITATION.cff").read_text(encoding="utf-8")
    try:
        citation_data = yaml.safe_load(citation)
    except yaml.YAMLError as exc:
        fail(f"CITATION.cff is not valid YAML: {exc}")
    if not isinstance(citation_data, dict):
        fail("CITATION.cff must contain a YAML mapping")
    if citation_data.get("cff-version") != "1.2.0":
        fail("CITATION.cff cff-version must be 1.2.0")
    for required_field in ("title", "type", "authors", "version", "license", "abstract"):
        if not citation_data.get(required_field):
            fail(f"CITATION.cff is missing required field {required_field!r}")
    if citation_data.get("version") != version:
        fail("CITATION.cff version does not match project version")
    release_date_value = citation_data.get("date-released")
    release_date = None
    if release_date_value is not None:
        try:
            if isinstance(release_date_value, dt.date):
                release_date = release_date_value
            else:
                release_date = dt.date.fromisoformat(str(release_date_value))
        except ValueError:
            fail("CITATION.cff date-released is not a valid ISO calendar date")
        if release_date > dt.date.today():
            fail("CITATION.cff date-released cannot be in the future")
    if require_release_date and release_date is None:
        fail("CITATION.cff date-released must be set to the actual release date for a final release build")

    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    license_text = (ROOT / "LICENSE").read_text(encoding="utf-8")
    if f"v{version}" not in readme.splitlines()[2]:
        fail("README status line does not identify the current version")
    if not changelog.startswith(f"# Changelog\n\n## {version} "):
        fail("CHANGELOG.md does not start with the current version")
    if "WhatsApp Traceability Research Lab contributors" not in license_text:
        fail("LICENSE copyright line has not been updated for the current project name")
    if not (ROOT / "SECURITY.md").is_file() or not (ROOT / "CONTRIBUTING.md").is_file():
        fail("SECURITY.md and CONTRIBUTING.md are required for a public research repository")
    if not (ROOT / ".gitignore").is_file():
        fail(".gitignore is required")
    gitignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
    for required_ignore in (".env", "*_private.pem", "private_key.pem", "artifacts/", "dist/"):
        if required_ignore not in gitignore:
            fail(f".gitignore is missing required safety/working-file pattern {required_ignore!r}")

    # Ensure all third-party GitHub Actions are immutable full-SHA references
    # and the required cross-platform Python matrix remains present.
    workflow_path = ROOT / ".github" / "workflows" / "ci.yml"
    if not workflow_path.is_file():
        fail(".github/workflows/ci.yml is missing")
    workflow = workflow_path.read_text(encoding="utf-8")
    try:
        workflow_data = yaml.safe_load(workflow)
    except yaml.YAMLError as exc:
        fail(f"CI workflow is not valid YAML: {exc}")
    jobs = workflow_data.get("jobs") if isinstance(workflow_data, dict) else None
    if not isinstance(jobs, dict) or not {"test", "packaging"}.issubset(jobs):
        fail("CI workflow must define both the test matrix and packaging jobs")
    matrix = jobs.get("test", {}).get("strategy", {}).get("matrix", {})
    matrix_os = set(matrix.get("os", []))
    matrix_python = {str(v) for v in matrix.get("python-version", [])}
    if not {"ubuntu-latest", "windows-latest", "macos-latest"}.issubset(matrix_os):
        fail("CI test matrix must cover Ubuntu, Windows, and macOS")
    if not {"3.11", "3.12", "3.13"}.issubset(matrix_python):
        fail("CI test matrix must cover Python 3.11, 3.12, and 3.13")
    action_refs = re.findall(r"(?m)^\s*-\s*uses:\s*([^\s#]+)", workflow)
    for action_ref in action_refs:
        if action_ref.startswith("./"):
            continue
        if not re.fullmatch(r"[^@]+@[0-9a-f]{40}", action_ref):
            fail(f"GitHub Action is not pinned to a full 40-character commit SHA: {action_ref}")
    for token in ("ubuntu-latest", "windows-latest", "macos-latest", '"3.11"', '"3.12"', '"3.13"'):
        if token not in workflow:
            fail(f"CI workflow is missing required OS/Python matrix entry {token!r}")
    if "name: Build and validate distributions" not in workflow or "scripts/build_release.py" not in workflow:
        fail("CI workflow must include the distribution build/validation job")
    release_job = jobs.get("release")
    if not isinstance(release_job, dict):
        fail("CI workflow must define the tag-triggered GitHub Release job")
    if "startsWith(github.ref, 'refs/tags/v')" not in str(release_job.get("if", "")):
        fail("release job must only publish version tags")
    release_needs = release_job.get("needs", [])
    if isinstance(release_needs, str):
        release_needs = [release_needs]
    if not {"test", "packaging"}.issubset(set(release_needs)):
        fail("release job must wait for the full test matrix and packaging job")
    if release_job.get("permissions", {}).get("contents") != "write":
        fail("release job must declare narrow contents: write permission")
    if "scripts/build_release.py --final-release" not in workflow or "gh release create" not in workflow:
        fail("release job must rebuild final artifacts and publish them through gh release")
    for smoke_marker in (
        "wheel-demo-case", "wheel-comparison.json", "sdist-demo-case", "sdist-comparison.json",
        ".wheel-smoke/bin/python -m pip check", ".sdist-smoke/bin/python -m pip check",
    ):
        if smoke_marker not in workflow:
            fail(f"packaging workflow is missing installed-distribution smoke test {smoke_marker!r}")

    # Parse every checked-in JSON schema and validate the current generated examples.
    schemas: dict[str, dict] = {}
    for schema_path in sorted((ROOT / "schemas").glob("*.schema.json")):
        try:
            schema = json.loads(schema_path.read_text(encoding="utf-8"))
            jsonschema.Draft202012Validator.check_schema(schema)
        except Exception as exc:
            fail(f"invalid schema {schema_path.relative_to(ROOT)}: {exc}")
        schemas[schema_path.name] = schema

    example_pairs = (
        ("examples/benchmark-report-2026-10-23.json", "benchmark-report.schema.json"),
        ("examples/protocol-comparison-sample-v0.5.2.json", "protocol-comparison.schema.json"),
        ("examples/merkle-inclusion-proof.json", "merkle-inclusion-proof.schema.json"),
    )
    for example_rel, schema_name in example_pairs:
        example_path = ROOT / example_rel
        try:
            payload = json.loads(example_path.read_text(encoding="utf-8"))
            jsonschema.validate(payload, schemas[schema_name])
        except Exception as exc:
            fail(f"example {example_rel} failed {schema_name}: {exc}")

    benchmark = json.loads((ROOT / "examples/benchmark-report-2026-10-23.json").read_text(encoding="utf-8"))
    comparison = json.loads((ROOT / "examples/protocol-comparison-sample-v0.5.2.json").read_text(encoding="utf-8"))
    if benchmark.get("opentrace_version") != version:
        fail("benchmark example version is stale")
    summary = comparison.get("summary", {})
    if summary.get("protocol_count") != 5 or summary.get("interoperable_protocols") != [] or summary.get("all_correct") is not True:
        fail("current comparison example must describe five correct synthetic/non-interoperable adapters")

    # Verify the complete synthetic demonstration bundle, including signature and inventory.
    try:
        result = verify_case(ROOT / "examples/demo-case")
    except Exception as exc:
        fail(f"synthetic example case failed integrity verification: {exc}")
    if not result:
        fail("synthetic example case verification returned an empty result")

    # Scan text assets for high-confidence private-key and common token markers.
    hits: list[str] = []
    for path in ROOT.rglob("*"):
        if not path.is_file() or any(part in SKIP_DIRS or part.endswith(".egg-info") for part in path.parts):
            continue
        if path.suffix.lower() in {".zip", ".gz", ".whl", ".pyc", ".sqlite", ".db"}:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        if PRIVATE_KEY_MARKER.search(text) or any(pattern.search(text) for pattern in TOKEN_PATTERNS):
            hits.append(str(path.relative_to(ROOT)))
    if hits:
        fail("high-confidence secret marker(s) found in: " + ", ".join(hits))

    print(f"PASS: project/package/citation versions agree at {version}")
    print(f"PASS: {len(schemas)} JSON schemas parse and pass Draft 2020-12 meta-schema checks")
    print(f"PASS: {len(example_pairs)} current examples validate against their schemas")
    print("PASS: synthetic case signature, file inventory, and manifest verify")
    print("PASS: no high-confidence private-key or common token markers found in scanned text files")
    print(f"PASS: {len(action_refs)} external GitHub Actions are pinned to full commit SHAs")
    print("PASS: CI workflow YAML parses; test matrix covers required OS/Python combinations and packaging smoke tests")
    print("PASS: ignore protections and publication guardrails are present")
    repository_url = citation_data.get("repository-code")
    repository_match = re.fullmatch(r"https://github\.com/([^/\s]+)/whatsapp-traceability-research(?:\.git)?/?", repository_url) if isinstance(repository_url, str) else None
    if not repository_match:
        if repository_url:
            fail("CITATION.cff repository-code must be the canonical URL for the whatsapp-traceability-research GitHub repository")
        print("BLOCKER: CITATION.cff repository-code is not set; add the real GitHub URL after creating the repository, then rebuild artifacts.")
        if not allow_missing_repository_code:
            return 2
        print("WARN: continuing in local pre-repository mode only; this option must not be used by hosted CI or for a tagged release.")
    else:
        owner = repository_match.group(1)
        if owner.upper() in {"OWNER", "USERNAME", "ORG", "ORGANIZATION"}:
            fail("CITATION.cff repository-code must use the actual GitHub owner, not a placeholder")
        print("PASS: CITATION.cff has the canonical whatsapp-traceability-research repository URL")
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--allow-missing-repository-code",
        action="store_true",
        help="allow a local audit before a real GitHub repository URL is known (not for CI/release tags)",
    )
    parser.add_argument(
        "--require-release-date",
        action="store_true",
        help="require a valid, non-future date-released field for final release artifacts",
    )
    args = parser.parse_args()
    raise SystemExit(
        audit(
            allow_missing_repository_code=args.allow_missing_repository_code,
            require_release_date=args.require_release_date,
        )
    )
