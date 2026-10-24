from __future__ import annotations

import json
from pathlib import Path

from opentrace.comparison import COMPARISON_SCHEMA, comparison_markdown, compare_protocols


def test_comparison_covers_three_adapters_and_is_explicit_about_interoperability():
    report = compare_protocols(message_size=16, hops=3, tree_depth=2, branching_factor=2, repeats=1)
    assert report["schema"] == COMPARISON_SCHEMA
    assert report["summary"]["protocol_count"] == 5
    assert report["summary"]["all_correct"] is True
    assert report["summary"]["interoperable_protocols"] == []
    assert set(report["summary"]["source_only_protocols"]) == {"source-tracking2021-synthetic", "hts-2025-synthetic", "minimal-trust-2026-synthetic"}
    assert set(report["summary"]["tree_disclosing_protocols"]) == {"traceback2019-synthetic-tree"}
    assert all(r["reference_status"] == "synthetic" for r in report["records"])
    assert all(r["caveat"].startswith("Synthetic research adapter") for r in report["records"])


def test_comparison_disclosure_profiles_match_research_properties():
    report = compare_protocols(message_size=8, hops=2, tree_depth=1, branching_factor=2, repeats=1)
    by_id = {r["protocol_id"]: r for r in report["records"]}
    path = by_id["traceback2019-synthetic-path"]["capabilities"]
    tree = by_id["traceback2019-synthetic-tree"]["capabilities"]
    source = by_id["source-tracking2021-synthetic"]["capabilities"]
    hts = by_id["hts-2025-synthetic"]["capabilities"]
    minimal = by_id["minimal-trust-2026-synthetic"]["capabilities"]
    assert path["reveals_intermediate_hops"] is True
    assert path["reveals_full_forwarding_tree"] is False
    assert tree["reveals_full_forwarding_tree"] is True
    assert source["complaint_based"] is True
    assert source["reveals_intermediate_hops"] is False
    assert source["disclosure_mode"] == "source_only"
    assert hts["reveals_intermediate_hops"] is False
    assert "source_only" in hts["disclosure_mode"]
    assert minimal["reveals_intermediate_hops"] is False
    assert minimal["complaint_based"] is True


def test_comparison_report_matches_schema_and_markdown_is_generated():
    import pytest
    jsonschema = pytest.importorskip("jsonschema")
    root = Path(__file__).resolve().parents[1]
    schema = json.loads((root / "schemas" / "protocol-comparison.schema.json").read_text(encoding="utf-8"))
    report = compare_protocols(message_size=8, hops=1, tree_depth=1, branching_factor=2, repeats=1)
    jsonschema.validate(report, schema)
    markdown = comparison_markdown(report)
    assert "# WhatsApp Traceability Research Lab Protocol Comparison" in markdown
    assert "source-tracking2021-synthetic" in markdown
    assert "hts-2025-synthetic" in markdown
    assert "minimal-trust-2026-synthetic" in markdown
    assert "not wire-compatible" in markdown


def test_comparison_rejects_unsafe_workloads():
    for kwargs in (
        {"message_size": 0},
        {"hops": 0},
        {"tree_depth": 7},
        {"branching_factor": 1},
        {"repeats": 101},
    ):
        try:
            compare_protocols(**kwargs)
        except ValueError:
            pass
        else:
            raise AssertionError(f"expected ValueError for {kwargs}")
