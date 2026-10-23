"""Common comparison harness for OpenTrace traceability research adapters.

The comparison layer intentionally normalizes *research properties*, not wire
protocol behavior. All adapters currently included here are synthetic and are
marked as non-interoperable with their cited papers.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import statistics
import time
from pathlib import Path
from typing import Any, Literal, Protocol

from . import __version__
from .protocols.source_tracking2021 import SourceTracking2021Synthetic
from .protocols.hts2025 import HopTrackingSignatures2025Synthetic
from .protocols.minimal_trust2026 import MinimalTrustTraceability2026Synthetic
from .protocols.traceback2019 import build_path
from .protocols.traceback2019_tree import (
    SyntheticTreeServer,
    TraceTree,
    new_message as new_tree_message,
    synthetic_send as tree_send,
)

COMPARISON_SCHEMA = "opentrace.protocol-comparison.v1"
ReferenceStatus = Literal["synthetic", "reference", "interoperable"]


class TraceabilityAdapter(Protocol):
    protocol_id: str
    reference_status: ReferenceStatus

    def capability_profile(self) -> dict[str, Any]: ...


@dataclass(frozen=True)
class AdapterProfile:
    protocol_id: str
    reference_status: ReferenceStatus
    capabilities: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return {
            "protocol_id": self.protocol_id,
            "reference_status": self.reference_status,
            "capabilities": self.capabilities,
        }


def _median(values: list[int]) -> int:
    return int(statistics.median(values))


def _tree_to_dict(tree: TraceTree) -> dict[str, Any]:
    return {"uid": tree.uid, "children": [_tree_to_dict(c) for c in tree.children]}


def _tree_size(tree: TraceTree) -> tuple[int, int]:
    nodes = 1
    edges = 0
    for child in tree.children:
        child_nodes, child_edges = _tree_size(child)
        nodes += child_nodes
        edges += child_edges + 1
    return nodes, edges


def _build_tree_workload(
    message: bytes, depth: int, branching_factor: int
) -> tuple[SyntheticTreeServer, TraceTree, int, Any]:
    server = SyntheticTreeServer()
    adjacency: dict[int, list[int]] = {}
    next_node_id = 1
    leaves: list[tuple[int, Any]] = []

    def expand(sender_id: int, metadata: Any, remaining: int) -> None:
        nonlocal next_node_id
        if remaining == 0:
            leaves.append((sender_id, metadata))
            return
        children: list[tuple[int, Any]] = []
        for counter in range(branching_factor):
            receiver = next_node_id
            next_node_id += 1
            receiver_md = tree_send(server, message, metadata, counter, sender_id, receiver)
            adjacency.setdefault(sender_id, []).append(receiver)
            children.append((receiver, receiver_md))
        for receiver, receiver_md in children:
            expand(receiver, receiver_md, remaining - 1)

    expand(0, new_tree_message(), depth)

    def expected(uid: int) -> TraceTree:
        return TraceTree(uid, tuple(expected(c) for c in adjacency.get(uid, [])))

    leaf_id, leaf_md = leaves[-1]
    return server, expected(0), leaf_id, leaf_md


def _path_profile() -> AdapterProfile:
    return AdapterProfile(
        "traceback2019-synthetic-path",
        "synthetic",
        {
            "finds_source": True,
            "reveals_intermediate_hops": True,
            "reveals_full_forwarding_tree": False,
            "complaint_based": False,
            "disclosure_mode": "path",
            "default_disclosure": "recipient_to_origin_path",
            "metadata_surface": "forwarding-path-linked server state",
            "collusion_model": "synthetic server state is trusted for the experiment",
            "authorization_model": "out_of_band",
        },
    )


def _tree_profile() -> AdapterProfile:
    return AdapterProfile(
        "traceback2019-synthetic-tree",
        "synthetic",
        {
            "finds_source": True,
            "reveals_intermediate_hops": True,
            "reveals_full_forwarding_tree": True,
            "complaint_based": False,
            "disclosure_mode": "full_synthetic_forwarding_tree",
            "default_disclosure": "full_tree_for_demo",
            "metadata_surface": "forwarding-tree-linked server state",
            "collusion_model": "synthetic server state is trusted for the experiment",
            "authorization_model": "out_of_band",
        },
    )


def _source_profile() -> AdapterProfile:
    return AdapterProfile(
        "source-tracking2021-synthetic",
        "synthetic",
        {
            "finds_source": True,
            "reveals_intermediate_hops": False,
            "reveals_full_forwarding_tree": False,
            "complaint_based": True,
            "disclosure_mode": "source_only",
            "default_disclosure": "source_only",
            "metadata_surface": "source receipt and complaint token",
            "collusion_model": "synthetic authority key is trusted for the experiment",
            "authorization_model": "synthetic complaint",
        },
    )


def _hts_profile() -> AdapterProfile:
    return AdapterProfile(
        "hts-2025-synthetic",
        "synthetic",
        {
            "finds_source": True,
            "reveals_intermediate_hops": False,
            "reveals_full_forwarding_tree": False,
            "complaint_based": False,
            "disclosure_mode": "source_only_after_hop_threshold",
            "default_disclosure": "source_only_when_trace_threshold_met",
            "metadata_surface": "threshold parameters and didactic opaque-payload proxy",
            "collusion_model": "paper studies malicious servers; current model has no cryptographic adversary simulation",
            "authorization_model": "hop-threshold eligibility model; not an authorization system",
        },
    )


def _minimal_trust_profile() -> AdapterProfile:
    return AdapterProfile(
        "minimal-trust-2026-synthetic",
        "synthetic",
        {
            "finds_source": True,
            "reveals_intermediate_hops": False,
            "reveals_full_forwarding_tree": False,
            "complaint_based": True,
            "disclosure_mode": "source_only_after_policy_gates",
            "default_disclosure": "source_only_after_all_policy_gates",
            "metadata_surface": "report threshold, regulator blocklist decision, moderator approval, and platform release gate",
            "collusion_model": "illustrates paper's one-honest-participant model; no cryptographic enforcement implemented",
            "authorization_model": "multi-party policy-gate simulation",
        },
    )


def adapter_profiles() -> list[AdapterProfile]:
    """Return normalized profiles for the currently included research models."""
    return [_path_profile(), _tree_profile(), _source_profile(), _hts_profile(), _minimal_trust_profile()]


def _path_run(message: bytes, hops: int, repeats: int) -> dict[str, Any]:
    construction: list[int] = []
    tracing: list[int] = []
    path: list[int] = []
    for _ in range(repeats):
        start = time.perf_counter_ns()
        server, metadata = build_path(message, hops)
        construction.append(time.perf_counter_ns() - start)
        start = time.perf_counter_ns()
        path = server.trace(message, metadata, hops)
        tracing.append(time.perf_counter_ns() - start)
    expected = list(range(hops, -1, -1))
    response = {"mode": "path", "recipient_to_origin_ids": path}
    return {
        "correct": path == expected,
        "scenario_nodes": hops + 1,
        "nodes_recovered": len(path),
        "edges_recovered": max(0, len(path) - 1),
        "construction_ns_median": _median(construction),
        "trace_ns_median": _median(tracing),
        "proof_or_trace_bytes": len(json.dumps(response, separators=(",", ":")).encode()),
        "storage_entries": len(server._state),
        "samples_ns": {"construction": construction, "trace": tracing},
    }


def _tree_run(message: bytes, depth: int, branching_factor: int, repeats: int) -> dict[str, Any]:
    construction: list[int] = []
    tracing: list[int] = []
    final = TraceTree(0)
    truth = TraceTree(0)
    for _ in range(repeats):
        start = time.perf_counter_ns()
        server, truth, leaf_id, leaf_md = _build_tree_workload(message, depth, branching_factor)
        construction.append(time.perf_counter_ns() - start)
        start = time.perf_counter_ns()
        final = server.trace(message, leaf_md, leaf_id)
        tracing.append(time.perf_counter_ns() - start)
    nodes, edges = _tree_size(final)
    expected_nodes, expected_edges = _tree_size(truth)
    response = {"mode": "tree", "tree": _tree_to_dict(final)}
    return {
        "correct": final == truth,
        "scenario_nodes": expected_nodes,
        "nodes_recovered": nodes,
        "edges_recovered": edges,
        "construction_ns_median": _median(construction),
        "trace_ns_median": _median(tracing),
        "proof_or_trace_bytes": len(json.dumps(response, separators=(",", ":")).encode()),
        "storage_entries": len(server._state),
        "expected_edges": expected_edges,
        "samples_ns": {"construction": construction, "trace": tracing},
    }


def _source_run(message: bytes, repeats: int, scenario_nodes: int) -> dict[str, Any]:
    issue: list[int] = []
    complaint: list[int] = []
    tracing: list[int] = []
    disclosure = None
    for _ in range(repeats):
        protocol = SourceTracking2021Synthetic(authority_key=b"comparison-authority".ljust(32, b"\0"))
        start = time.perf_counter_ns()
        receipt = protocol.issue_receipt(message, "account-origin")
        issue.append(time.perf_counter_ns() - start)
        start = time.perf_counter_ns()
        proof = protocol.create_complaint(receipt)
        complaint.append(time.perf_counter_ns() - start)
        start = time.perf_counter_ns()
        disclosure = protocol.trace_source(proof)
        tracing.append(time.perf_counter_ns() - start)
    assert disclosure is not None
    response = {
        "source_account": disclosure.source_account,
        "disclosed_forwarders": disclosure.disclosed_forwarders,
    }
    return {
        "correct": disclosure.source_account == "account-origin",
        "scenario_nodes": scenario_nodes,
        "nodes_recovered": 1,
        "edges_recovered": 0,
        "construction_ns_median": _median(issue),
        "trace_ns_median": _median(tracing),
        "complaint_ns_median": _median(complaint),
        "proof_or_trace_bytes": len(json.dumps(response, separators=(",", ":")).encode()),
        "storage_entries": 1,
        "samples_ns": {"issue": issue, "complaint": complaint, "trace": tracing},
    }


def _hts_run(
    message: bytes,
    hops: int,
    repeats: int,
    anonymity_threshold_hops: int,
    trace_threshold_hops: int,
) -> dict[str, Any]:
    construction: list[int] = []
    tracing: list[int] = []
    final = None
    for _ in range(repeats):
        start = time.perf_counter_ns()
        protocol = HopTrackingSignatures2025Synthetic(
            anonymity_threshold_hops=anonymity_threshold_hops,
            trace_threshold_hops=trace_threshold_hops,
        )
        construction.append(time.perf_counter_ns() - start)
        start = time.perf_counter_ns()
        final = protocol.evaluate(message, hops)
        tracing.append(time.perf_counter_ns() - start)
    assert final is not None
    trace_output = {
        "source_recovered": final.source_recovered,
        "disclosed_forwarders": final.disclosed_forwarders,
        "threshold_gap_hops": final.threshold_gap_hops,
        "didactic_payload_size_proxy_bytes": final.didactic_payload_size_proxy_bytes,
    }
    nodes_recovered = 1 if final.source_recovered else 0
    return {
        "correct": final.source_recovered == (hops >= trace_threshold_hops),
        "scenario_nodes": hops + 1,
        "nodes_recovered": nodes_recovered,
        "edges_recovered": 0,
        "construction_ns_median": _median(construction),
        "trace_ns_median": _median(tracing),
        "proof_or_trace_bytes": len(json.dumps(trace_output, separators=(",", ":")).encode()),
        "storage_entries": 0,
        "trace_eligible": final.source_recovered,
        "anonymity_threshold_hops": anonymity_threshold_hops,
        "trace_threshold_hops": trace_threshold_hops,
        "threshold_gap_hops": final.threshold_gap_hops,
        "succinctness_result_from_paper_model": final.succinctness_result_from_paper_model,
        "didactic_payload_size_proxy_bytes": final.didactic_payload_size_proxy_bytes,
        "samples_ns": {"construction": construction, "trace": tracing},
    }


def _minimal_trust_run(hops: int, repeats: int) -> dict[str, Any]:
    construction: list[int] = []
    tracing: list[int] = []
    valid_decision = None
    innocent_decision = None
    protocol = MinimalTrustTraceability2026Synthetic()
    for _ in range(repeats):
        start = time.perf_counter_ns()
        protocol = MinimalTrustTraceability2026Synthetic()
        construction.append(time.perf_counter_ns() - start)
        start = time.perf_counter_ns()
        valid_decision = protocol.assess_trace(
            source_account="account-origin",
            verified_distinct_reports=3,
            required_reports=3,
            regulator_blocklist_match=True,
            moderator_approved=True,
            platform_release_authorized=True,
        )
        # Model an innocent message: a required independent gate rejects it.
        innocent_decision = protocol.assess_trace(
            source_account="account-innocent-control",
            verified_distinct_reports=3,
            required_reports=3,
            regulator_blocklist_match=False,
            moderator_approved=True,
            platform_release_authorized=True,
        )
        tracing.append(time.perf_counter_ns() - start)
    assert valid_decision is not None and innocent_decision is not None
    payload = {
        "trace_allowed": valid_decision.trace_allowed,
        "source_account": valid_decision.source_account,
        "innocent_trace_blocked": not innocent_decision.trace_allowed,
    }
    nodes_recovered = 1 if valid_decision.trace_allowed else 0
    return {
        "correct": valid_decision.trace_allowed and not innocent_decision.trace_allowed,
        "scenario_nodes": hops + 1,
        "nodes_recovered": nodes_recovered,
        "edges_recovered": 0,
        "construction_ns_median": _median(construction),
        "trace_ns_median": _median(tracing),
        "proof_or_trace_bytes": len(json.dumps(payload, separators=(",", ":")).encode()),
        "storage_entries": 0,
        "valid_case_trace_allowed": valid_decision.trace_allowed,
        "innocent_case_trace_blocked": not innocent_decision.trace_allowed,
        "required_reports": valid_decision.required_reports,
        "policy_gates": [
            "verified_distinct_report_threshold",
            "regulator_blocklist_match",
            "moderator_approval",
            "platform_release_authorization",
        ],
        "single_honest_role_scenarios": protocol.single_honest_role_scenarios(required_reports=3),
        "samples_ns": {"construction": construction, "trace": tracing},
    }


def compare_protocols(
    *,
    message_size: int = 256,
    hops: int = 8,
    tree_depth: int = 3,
    branching_factor: int = 2,
    repeats: int = 5,
    hts_anonymity_threshold_hops: int = 2,
    hts_trace_threshold_hops: int = 4,
) -> dict[str, Any]:
    """Run one controlled scenario across all currently implemented adapters."""
    if not 1 <= message_size <= 1_000_000:
        raise ValueError("message_size must be between 1 and 1000000")
    if not 1 <= hops <= 256:
        raise ValueError("hops must be between 1 and 256")
    if not 1 <= tree_depth <= 6:
        raise ValueError("tree_depth must be between 1 and 6")
    if not 2 <= branching_factor <= 5:
        raise ValueError("branching_factor must be between 2 and 5")
    if not 1 <= repeats <= 100:
        raise ValueError("repeats must be between 1 and 100")
    if not 0 <= hts_anonymity_threshold_hops <= 256:
        raise ValueError("hts_anonymity_threshold_hops must be between 0 and 256")
    if not 1 <= hts_trace_threshold_hops <= 256:
        raise ValueError("hts_trace_threshold_hops must be between 1 and 256")
    if hts_trace_threshold_hops <= hts_anonymity_threshold_hops:
        raise ValueError("HTS trace threshold must exceed the anonymity threshold")
    estimated_tree_nodes = sum(branching_factor**level for level in range(tree_depth + 1))
    if repeats * estimated_tree_nodes > 100_000:
        raise ValueError("comparison workload exceeds 100000 tree node-runs")

    message = b"M" * message_size
    profiles = {p.protocol_id: p for p in adapter_profiles()}
    path_measurements = _path_run(message, hops, repeats)
    tree_measurements = _tree_run(message, tree_depth, branching_factor, repeats)
    source_measurements = _source_run(message, repeats, hops + 1)
    hts_measurements = _hts_run(
        message,
        hops,
        repeats,
        hts_anonymity_threshold_hops,
        hts_trace_threshold_hops,
    )
    minimal_trust_measurements = _minimal_trust_run(hops, repeats)

    measurements = {
        "traceback2019-synthetic-path": path_measurements,
        "traceback2019-synthetic-tree": tree_measurements,
        "source-tracking2021-synthetic": source_measurements,
        "hts-2025-synthetic": hts_measurements,
        "minimal-trust-2026-synthetic": minimal_trust_measurements,
    }
    records: list[dict[str, Any]] = []
    for protocol_id, measurement in measurements.items():
        profile = profiles[protocol_id]
        outcome = {
            "correct": measurement["correct"],
            "scenario_nodes": measurement["scenario_nodes"],
            "nodes_recovered": measurement["nodes_recovered"],
            "edges_recovered": measurement["edges_recovered"],
            "node_disclosure_fraction": round(
                measurement["nodes_recovered"] / measurement["scenario_nodes"], 6
            ),
        }
        records.append(
            {
                "protocol_id": protocol_id,
                "reference_status": profile.reference_status,
                "capabilities": profile.capabilities,
                "measurements": {k: v for k, v in measurement.items() if k != "samples_ns"},
                "outcome": outcome,
                "samples_ns": measurement["samples_ns"],
                "caveat": "Synthetic research adapter; not wire-compatible with the cited paper or a deployed messenger.",
            }
        )

    return {
        "schema": COMPARISON_SCHEMA,
        "opentrace_version": __version__,
        "generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "scenario": {
            "message_bytes": message_size,
            "linear_hops": hops,
            "tree_depth": tree_depth,
            "branching_factor": branching_factor,
            "repeats": repeats,
        },
        "records": records,
        "summary": {
            "protocol_count": len(records),
            "all_correct": all(r["outcome"]["correct"] for r in records),
            "source_only_protocols": [
                r["protocol_id"] for r in records
                if str(r["capabilities"]["disclosure_mode"]).startswith("source_only")
            ],
            "tree_disclosing_protocols": [
                r["protocol_id"] for r in records if r["capabilities"]["reveals_full_forwarding_tree"]
            ],
            "interoperable_protocols": [
                r["protocol_id"] for r in records if r["reference_status"] == "interoperable"
            ],
        },
    }


def write_comparison_report(report: dict[str, Any], path: str | Path) -> Path:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return destination


def comparison_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# WhatsApp Traceability Research Lab Protocol Comparison",
        "",
        "> Research comparison only. Current adapters are synthetic and are not wire-compatible with deployed messaging systems.",
        "",
        "## Scenario",
        "",
        f"- Message size: **{report['scenario']['message_bytes']} bytes**",
        f"- Linear path: **{report['scenario']['linear_hops']} hops**",
        f"- Tree: **depth {report['scenario']['tree_depth']} / branching {report['scenario']['branching_factor']}**",
        f"- Repeats: **{report['scenario']['repeats']}**",
        "",
        "## Comparison",
        "",
        "| Protocol | Source | Intermediate hops | Full tree | Complaint | Disclosure | Trace median | Output bytes |",
        "|---|---:|---:|---:|---:|---|---:|---:|",
    ]
    for record in report["records"]:
        c = record["capabilities"]
        m = record["measurements"]
        lines.append(
            f"| `{record['protocol_id']}` | {'yes' if c['finds_source'] else 'no'} | "
            f"{'yes' if c['reveals_intermediate_hops'] else 'no'} | "
            f"{'yes' if c['reveals_full_forwarding_tree'] else 'no'} | "
            f"{'yes' if c['complaint_based'] else 'no'} | `{c['disclosure_mode']}` | "
            f"{m['trace_ns_median']} ns | {m['proof_or_trace_bytes']} |"
        )
    lines += [
        "",
        "## Interpretation",
        "",
        "- **Path traceback** is useful when the research question is the chain from a reported recipient back toward the source.",
        "- **Tree traceback** trades greater disclosure for visibility into the synthetic forwarding tree.",
        "- **Source-only tracking** minimizes forwarding disclosure: the model resolves the source under a complaint without returning intermediate hops.",
        "- **HTS threshold modeling** illustrates the published threshold-gap result; its payload-size proxy is pedagogical, not a measured signature size or cryptographic implementation.",
        "- **Minimal-trust modeling** gates disclosure on reports, a regulator blocklist decision, moderator approval, and platform release authorization; gates are simulated rather than cryptographically enforced.",
        "- A protocol marked **synthetic** must not be presented as interoperable with WhatsApp, Signal, or another production messenger.",
        "",
        "## Security interpretation",
        "",
        "These measurements compare this laboratory's models, not real-world cryptographic security. Production claims require a faithful specification, formal security analysis, independent implementation review, test vectors, and interoperability testing.",
        "",
    ]
    return "\n".join(lines)
