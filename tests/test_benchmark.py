from __future__ import annotations

from opentrace.benchmark import BENCHMARK_SCHEMA, run_benchmark


def test_unified_benchmark_has_correct_synthetic_path_and_tree_records():
    report = run_benchmark(
        message_size=24,
        max_hops=2,
        max_tree_depth=3,
        branching_factors=(2,),
        repeats=1,
    )
    assert report["schema"] == BENCHMARK_SCHEMA
    assert report["summary"]["all_correct"] is True
    assert report["summary"]["record_count"] == 5  # two path records plus three tree depths
    assert all(record["interoperable_with_reference"] is False for record in report["records"])
    for record in report["records"]:
        assert record["outcome"]["correct"] is True
        assert record["measurements"]["construction_ns_median"] >= 0
        assert record["measurements"]["trace_ns_median"] >= 0
        assert len(record["samples_ns"]["trace"]) == 1
        assert record["outcome"]["node_disclosure_fraction"] == 1.0


def test_unified_benchmark_supports_multiple_branching_factors():
    report = run_benchmark(
        message_size=8,
        max_hops=1,
        max_tree_depth=2,
        branching_factors=(2, 3),
        repeats=1,
    )
    tree_records = [r for r in report["records"] if r["workload"]["kind"] == "complete_tree"]
    assert len(tree_records) == 4
    assert {r["workload"]["branching_factor"] for r in tree_records} == {2, 3}
    assert all(r["outcome"]["correct"] for r in tree_records)


def test_unified_benchmark_rejects_unsafe_or_invalid_bounds():
    for kwargs in (
        {"message_size": 0},
        {"max_hops": 0},
        {"max_tree_depth": 7},
        {"repeats": 101},
        {"branching_factors": (1,)},
        {"branching_factors": (2, 2)},
    ):
        try:
            run_benchmark(**kwargs)
        except ValueError:
            pass
        else:
            raise AssertionError(f"expected ValueError for {kwargs}")


def test_benchmark_report_matches_published_json_schema():
    import json
    from pathlib import Path
    import pytest

    jsonschema = pytest.importorskip("jsonschema")
    root = Path(__file__).resolve().parents[1]
    schema = json.loads((root / "schemas" / "benchmark-report.schema.json").read_text(encoding="utf-8"))
    report = run_benchmark(message_size=6, max_hops=1, max_tree_depth=1, branching_factors=(2,), repeats=1)
    jsonschema.validate(report, schema)


def test_benchmark_caps_aggregate_tree_workload():
    try:
        run_benchmark(max_tree_depth=6, branching_factors=(5,), repeats=100)
    except ValueError as exc:
        assert "exceeds 250000 node-runs" in str(exc)
    else:
        raise AssertionError("expected aggregate benchmark workload to be rejected")
def test_benchmark_reports_iqr_and_hardware_environment():
    report = run_benchmark(
        message_size=16,
        max_hops=2,
        max_tree_depth=1,
        branching_factors=(2,),
        repeats=5,
    )
    env = report["environment"]
    assert "machine" in env
    assert "processor" in env
    assert "cpu_count" in env and env["cpu_count"] >= 1
    assert "total_memory_bytes" in env

    for record in report["records"]:
        m = record["measurements"]
        assert "construction_ns_iqr" in m
        assert "trace_ns_iqr" in m
        assert m["construction_ns_iqr"] >= 0
        assert m["trace_ns_iqr"] >= 0
        assert m["construction_ns_max"] >= m["construction_ns_min"]
        assert m["trace_ns_max"] >= m["trace_ns_min"]


def test_benchmark_supports_explicit_path_hops():
    report = run_benchmark(
        message_size=16,
        path_hops=(2, 8),
        max_tree_depth=1,
        branching_factors=(2,),
        repeats=1,
    )
    path_records = [r for r in report["records"] if r["workload"]["kind"] == "linear"]
    assert len(path_records) == 2
    assert [r["workload"]["hops"] for r in path_records] == [2, 8]


def test_benchmark_rejects_invalid_path_hops():
    import pytest
    for bad_hops in ((), (0,), (257,), (2, 2), (-1,)):
        with pytest.raises(ValueError, match="path_hops"):
            run_benchmark(path_hops=bad_hops)
