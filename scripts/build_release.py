#!/usr/bin/env python3
"""Build checked WhatsApp Traceability Research Lab distributions and source ZIP.

A missing CITATION.cff repository-code can be tolerated only with the explicit
--allow-missing-repository-code candidate flag. Such outputs are not release-ready.
"""
from __future__ import annotations

import argparse
import hashlib
import shutil
import subprocess
import sys
import tomllib
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKIP_DIRS = {".git", ".pytest_cache", "__pycache__", ".venv", "venv", "build", "dist", "artifacts", "htmlcov"}
SKIP_SUFFIXES = {".pyc", ".pyo", ".sqlite", ".db"}


def included(path: Path) -> bool:
    relative = path.relative_to(ROOT)
    if any(part in SKIP_DIRS or part.endswith(".egg-info") for part in relative.parts):
        return False
    if path.suffix in SKIP_SUFFIXES or path.name in {".DS_Store", "Thumbs.db"}:
        return False
    return path.is_file()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--allow-missing-repository-code",
        action="store_true",
        help="build pre-repository candidates only; never tag/upload these as a release",
    )
    mode.add_argument(
        "--final-release",
        action="store_true",
        help="require real repository-code and date-released metadata before building final artifacts",
    )
    args = parser.parse_args()

    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    version = project["version"]
    audit_cmd = [sys.executable, str(ROOT / "scripts" / "release_audit.py")]
    if args.allow_missing_repository_code:
        audit_cmd.append("--allow-missing-repository-code")
    if args.final_release:
        audit_cmd.append("--require-release-date")
    subprocess.run(audit_cmd, cwd=ROOT, check=True)

    dist_root = ROOT / "dist"
    # Candidate builds are isolated from final outputs. A candidate build must
    # never delete or overwrite a release build, and all its checksummed files
    # must live under an explicitly named candidate directory.
    if args.allow_missing_repository_code:
        dist_dir = dist_root / "candidate"
        if dist_dir.exists():
            shutil.rmtree(dist_dir)
        dist_dir.mkdir(parents=True)
    else:
        dist_dir = dist_root
        if dist_dir.exists():
            shutil.rmtree(dist_dir)
        dist_dir.mkdir(parents=True)

    subprocess.run(
        [sys.executable, "-m", "build", "--sdist", "--wheel", "--outdir", str(dist_dir)],
        cwd=ROOT,
        check=True,
    )

    artifacts = sorted([*dist_dir.glob("*.whl"), *dist_dir.glob("*.tar.gz")])
    if len(artifacts) != 2:
        raise SystemExit(f"Expected exactly one wheel and one source distribution, found: {[p.name for p in artifacts]}")
    subprocess.run([sys.executable, "-m", "twine", "check", *(str(p) for p in artifacts)], cwd=ROOT, check=True)

    candidate_suffix = "-candidate" if args.allow_missing_repository_code else ""
    source_zip = dist_dir / f"e2ee-traceability-lab-v{version}-source{candidate_suffix}.zip"
    root_name = f"e2ee-traceability-lab-v{version}"
    with zipfile.ZipFile(source_zip, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in sorted(ROOT.rglob("*")):
            if not included(path):
                continue
            relative = path.relative_to(ROOT).as_posix()
            archive.write(path, f"{root_name}/{relative}")

    checksum_file = dist_dir / f"e2ee-traceability-lab-v{version}{'-candidate' if args.allow_missing_repository_code else ''}.sha256"
    checksummed = [*artifacts, source_zip]
    checksum_file.write_text("".join(f"{sha256(path)}  {path.name}\n" for path in sorted(checksummed)), encoding="utf-8")

    print("Built distributions:")
    for path in [*artifacts, source_zip, checksum_file]:
        print(f"  {path}  sha256={sha256(path)}")
    if args.allow_missing_repository_code:
        print("WARNING: candidate mode was used. Add CITATION.cff repository-code, rerun without the escape hatch, and rebuild before publishing.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
