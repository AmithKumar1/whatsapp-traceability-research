from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run_audit(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "release_audit.py"), *args],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )


def test_candidate_audit_is_explicit_about_repository_url_gate() -> None:
    result = run_audit("--allow-missing-repository-code")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "PASS: project/package/citation versions agree" in result.stdout
    if not re.search(r"(?m)^repository-code:\s*https://github\.com/", (ROOT / "CITATION.cff").read_text(encoding="utf-8")):
        assert "BLOCKER: CITATION.cff repository-code is not set" in result.stdout


def test_strict_audit_blocks_missing_repository_url() -> None:
    citation = (ROOT / "CITATION.cff").read_text(encoding="utf-8")
    result = run_audit()
    if re.search(r"(?m)^repository-code:\s*https://github\.com/", citation):
        assert result.returncode == 0, result.stdout + result.stderr
    else:
        assert result.returncode == 2
        assert "BLOCKER: CITATION.cff repository-code is not set" in result.stdout


def test_workflow_pins_all_external_actions_to_full_commit_shas() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    refs = re.findall(r"(?m)^\s*-\s*uses:\s*([^\s#]+)", workflow)
    assert refs, "workflow contains no actions"
    assert all(re.fullmatch(r"[^@]+@[0-9a-f]{40}", ref) or ref.startswith("./") for ref in refs), refs
    assert "windows-latest" in workflow and "macos-latest" in workflow and "ubuntu-latest" in workflow


def test_final_release_audit_requires_release_date() -> None:
    citation = (ROOT / "CITATION.cff").read_text(encoding="utf-8")
    has_repo = bool(re.search(r"(?m)^repository-code:\s*https://github\.com/", citation))
    has_date = bool(re.search(r"(?m)^date-released:\s*[0-9]{4}-[0-9]{2}-[0-9]{2}\s*$", citation))
    result = run_audit("--require-release-date")
    if not has_date:
        assert result.returncode == 1
        assert "date-released must be set" in result.stderr
    elif not has_repo:
        assert result.returncode == 2
        assert "BLOCKER: CITATION.cff repository-code is not set" in result.stdout
    else:
        assert result.returncode == 0, result.stdout + result.stderr


def test_final_builder_is_gated_by_complete_release_metadata() -> None:
    builder = (ROOT / "scripts" / "build_release.py").read_text(encoding="utf-8")
    assert "--final-release" in builder
    assert "--require-release-date" in builder
    result = run_audit("--require-release-date")
    assert result.returncode == 0, result.stdout + result.stderr


def test_tag_release_job_waits_for_all_tests_and_packaging() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "if: startsWith(github.ref, 'refs/tags/v')" in workflow
    assert "needs: [test, packaging]" in workflow
    assert "python scripts/build_release.py --final-release" in workflow
    assert "gh release create" in workflow


def test_packaging_smoke_tests_exercise_installed_distributions() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    for marker in ("wheel-demo-case", "wheel-comparison.json", "sdist-demo-case", "sdist-comparison.json"):
        assert marker in workflow
    assert ".wheel-smoke/bin/python -m pip check" in workflow
    assert ".sdist-smoke/bin/python -m pip check" in workflow


def test_release_audit_validates_workflow_yaml_and_job_matrix() -> None:
    result = run_audit("--allow-missing-repository-code")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "CI workflow YAML parses" in result.stdout
    assert "required OS/Python combinations" in result.stdout
