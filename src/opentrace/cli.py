from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .authorization import AuthorizationError, verify_authorization
from .authorization_demo import create_authorization_demo
from .benchmark import run_benchmark, write_benchmark_report
from .comparison import comparison_markdown, compare_protocols, write_comparison_report
from .demo import create_demo
from .integrity import IntegrityError, verify_case
from .strictjson import load_json
from .transparency import TransparencyError, build_inclusion_proof, merkle_root, verify_inclusion
from .protocols.traceback2019 import benchmark_points
from .protocols.traceback2019_tree import demo_tree
from .protocols.source_tracking2021 import SourceTracking2021Synthetic
from .protocols.hts2025 import HopTrackingSignatures2025Synthetic
from .protocols.minimal_trust2026 import MinimalTrustTraceability2026Synthetic


def _print_json(payload: object) -> None:
    print(json.dumps(payload, indent=2, ensure_ascii=False))


def main() -> None:
    parser = argparse.ArgumentParser(prog="e2ee-traceability", description="WhatsApp Traceability Research Lab: research and evaluation for encrypted-message traceability")
    sub = parser.add_subparsers(dest="command", required=True)

    bench_parser = sub.add_parser("benchmark", help="run the unified synthetic path/tree research benchmark")
    bench_parser.add_argument("--message-size", type=int, default=256)
    bench_parser.add_argument("--max-hops", type=int, default=32)
    bench_parser.add_argument("--max-tree-depth", type=int, default=3)
    bench_parser.add_argument("--branching-factors", default="2", help="comma-separated factors, each 2..5 (for example: 2,3)")
    bench_parser.add_argument("--repeats", type=int, default=3)
    bench_parser.add_argument("--out", type=Path, default=None, help="optional path to write the complete JSON report")

    demo_parser = sub.add_parser("demo", help="create a synthetic branching trace and signed evidence manifest")
    demo_parser.add_argument("--out", type=Path, required=True, help="output directory for the synthetic case")

    verify_parser = sub.add_parser("verify", help="verify the manifest, file inventory, record chain, and file hashes")
    verify_parser.add_argument("case_dir", type=Path, help="directory containing manifest.json")
    verify_parser.add_argument("--public-key", type=Path, default=None, help="separately trusted Ed25519 public key PEM")

    auth_demo = sub.add_parser("authorization-demo", help="create a synthetic multi-approver authorization fixture")
    auth_demo.add_argument("--out", type=Path, required=True, help="output directory for synthetic request and approvals")

    auth_check = sub.add_parser("authorize-check", help="verify a request against configured multi-party approval policy")
    auth_check.add_argument("--request", type=Path, required=True)
    auth_check.add_argument("--approvals", type=Path, required=True)
    auth_check.add_argument("--trust", type=Path, required=True, help="independently administered trusted principal registry")
    auth_check.add_argument("--policy", type=Path, required=True)

    merkle_demo = sub.add_parser("merkle-demo", help="create and verify one offline Merkle inclusion proof from synthetic entries")
    merkle_demo.add_argument("--out", type=Path, required=True, help="output JSON path")
    merkle_demo.add_argument("--index", type=int, default=2, help="synthetic entry index to prove (0-based)")

    sub.add_parser("traceback2019-tree-demo", help="run the synthetic 2019-style tree-traceback demo")

    compare_parser = sub.add_parser("compare", help="compare the implemented synthetic traceability adapters in one controlled scenario")
    compare_parser.add_argument("--message-size", type=int, default=256)
    compare_parser.add_argument("--hops", type=int, default=8)
    compare_parser.add_argument("--tree-depth", type=int, default=3)
    compare_parser.add_argument("--branching-factor", type=int, default=2)
    compare_parser.add_argument("--repeats", type=int, default=5)
    compare_parser.add_argument("--hts-anonymity-threshold-hops", type=int, default=2)
    compare_parser.add_argument("--hts-trace-threshold-hops", type=int, default=4)
    compare_parser.add_argument("--out", type=Path, default=None, help="optional JSON comparison report")
    compare_parser.add_argument("--markdown", type=Path, default=None, help="optional Markdown comparison report")

    sub.add_parser("source-tracking2021-demo", help="run the synthetic source-only disclosure research adapter")

    hts_demo = sub.add_parser("hts2025-demo", help="run the didactic, non-cryptographic HTS threshold model")
    hts_demo.add_argument("--message-size", type=int, default=64)
    hts_demo.add_argument("--hops", type=int, default=8)
    hts_demo.add_argument("--anonymity-threshold-hops", type=int, default=2)
    hts_demo.add_argument("--trace-threshold-hops", type=int, default=4)

    minimal_trust_demo = sub.add_parser("minimal-trust2026-demo", help="run the four-gate minimal-trust policy simulation")
    minimal_trust_demo.add_argument("--required-reports", type=int, default=3)

    traceback_bench = sub.add_parser("traceback2019-benchmark", help="benchmark the synthetic 2019 path-traceback research adapter")
    traceback_bench.add_argument("--message-size", type=int, default=256)
    traceback_bench.add_argument("--max-hops", type=int, default=32)
    traceback_bench.add_argument("--out", type=Path, default=None, help="optional JSON output path")

    merkle_verify = sub.add_parser("merkle-verify", help="verify an offline inclusion proof for supplied entry bytes")
    merkle_verify.add_argument("--proof", type=Path, required=True, help="proof JSON produced by merkle-demo or the proof API")
    entry_group = merkle_verify.add_mutually_exclusive_group(required=True)
    entry_group.add_argument("--entry-text", help="exact UTF-8 text bytes of the Merkle leaf")
    entry_group.add_argument("--entry-file", type=Path, help="file whose exact bytes are the Merkle leaf")

    tb_repro = sub.add_parser("traceback-reproduction", help="run the Tyagi et al. (CCS 2019) cryptographic path traceback reproduction experiment")
    tb_repro.add_argument("--hops", type=int, default=4, help="number of forwarding hops (1-50)")
    tb_repro.add_argument("--message", type=str, default="Synthetic viral message for Tyagi2019 reproduction", help="message content to trace")
    tb_repro.add_argument("--scenario", type=str, choices=["valid_linear_path", "tampered_content", "forged_signature", "missing_hop", "cyclic_forwarding"], default="valid_linear_path", help="experiment scenario")
    tb_repro.add_argument("--adversarial-hop", type=int, default=2, help="1-based index where adversarial fault occurs")
    tb_repro.add_argument("--pki-extension", action="store_true", default=False, help="enable experimental Ed25519 PKI non-repudiation extension (default is pure symmetric)")
    tb_repro.add_argument("--out", type=Path, default=None, help="optional JSON report output path")
    tb_repro.add_argument("--markdown", type=Path, default=None, help="optional Markdown summary output path")

    args = parser.parse_args()
    try:
        if args.command == "benchmark":
            factors = tuple(int(item.strip()) for item in args.branching_factors.split(",") if item.strip())
            report = run_benchmark(
                message_size=args.message_size,
                max_hops=args.max_hops,
                max_tree_depth=args.max_tree_depth,
                branching_factors=factors,
                repeats=args.repeats,
            )
            if args.out is not None:
                write_benchmark_report(report, args.out)
                _print_json({"report": str(args.out.resolve()), "schema": report["schema"], "summary": report["summary"]})
            else:
                _print_json(report)
        elif args.command == "demo":
            output = create_demo(args.out)
            print(f"Created synthetic case: {output}")
            print("No real communications are represented; this does not trace WhatsApp or reveal private history.")
            print(f"Verify it with: e2ee-traceability verify {output}")
        elif args.command == "verify":
            _print_json(verify_case(args.case_dir, args.public_key))
        elif args.command == "authorization-demo":
            result = create_authorization_demo(args.out)
            print(f"Created synthetic authorization fixture: {args.out.resolve()}")
            _print_json(result)
        elif args.command == "authorize-check":
            request = load_json(args.request)
            approvals = load_json(args.approvals)
            trust = load_json(args.trust)
            policy = load_json(args.policy)
            if not isinstance(approvals, list):
                raise AuthorizationError("approvals file must contain a JSON array")
            result = verify_authorization(
                request, approvals, trust, policy, trust_base_dir=args.trust.resolve().parent
            )
            _print_json(result)
        elif args.command == "merkle-demo":
            entries = [f"synthetic-event-{i:03d}".encode("utf-8") for i in range(7)]
            proof = build_inclusion_proof(entries, args.index)
            proof_valid = verify_inclusion(entries[args.index], proof)
            if not proof_valid or proof["root_sha256"] != merkle_root(entries):
                raise TransparencyError("internal Merkle proof self-check failed")
            args.out.parent.mkdir(parents=True, exist_ok=True)
            args.out.write_text(json.dumps(proof, indent=2) + "\n", encoding="utf-8")
            print(f"Created and verified synthetic inclusion proof: {args.out.resolve()}")
            _print_json({"tree_size": proof["tree_size"], "leaf_index": proof["leaf_index"], "root_sha256": proof["root_sha256"], "proof_valid": proof_valid})
        elif args.command == "compare":
            report = compare_protocols(
                message_size=args.message_size,
                hops=args.hops,
                tree_depth=args.tree_depth,
                branching_factor=args.branching_factor,
                repeats=args.repeats,
                hts_anonymity_threshold_hops=args.hts_anonymity_threshold_hops,
                hts_trace_threshold_hops=args.hts_trace_threshold_hops,
            )
            if args.out is not None:
                write_comparison_report(report, args.out)
            if args.markdown is not None:
                args.markdown.parent.mkdir(parents=True, exist_ok=True)
                args.markdown.write_text(comparison_markdown(report), encoding="utf-8")
            _print_json({
                "schema": report["schema"],
                "json_report": str(args.out.resolve()) if args.out else None,
                "markdown_report": str(args.markdown.resolve()) if args.markdown else None,
                "summary": report["summary"],
            })
        elif args.command == "source-tracking2021-demo":
            source_protocol = SourceTracking2021Synthetic(authority_key=b"open-trace-demo-key-2026".ljust(32, b"\0"))
            receipt = source_protocol.issue_receipt(b"synthetic-viral-message", "account-origin")
            complaint = source_protocol.create_complaint(receipt)
            disclosure = source_protocol.trace_source(complaint)
            _print_json({"protocol": disclosure.protocol, "interoperable_with_reference": disclosure.interoperable_with_reference, "message_digest": disclosure.message_digest, "source_account": disclosure.source_account, "disclosed_forwarders": disclosure.disclosed_forwarders, "cryptographic_claim": disclosure.cryptographic_claim})
        elif args.command == "hts2025-demo":
            if args.message_size <= 0:
                raise ValueError("message-size must be positive")
            hts_protocol = HopTrackingSignatures2025Synthetic(
                anonymity_threshold_hops=args.anonymity_threshold_hops,
                trace_threshold_hops=args.trace_threshold_hops,
            )
            _print_json({
                **hts_protocol.evaluate(b"M" * args.message_size, args.hops).as_dict(),
                "caveat": "threshold-only didactic model; no cryptographic HTS implementation or interoperable signature",
            })
        elif args.command == "minimal-trust2026-demo":
            min_trust_protocol = MinimalTrustTraceability2026Synthetic()
            if args.required_reports < 2:
                raise ValueError("required-reports must be at least 2")
            valid = min_trust_protocol.assess_trace(
                source_account="synthetic-origin",
                verified_distinct_reports=args.required_reports,
                required_reports=args.required_reports,
                regulator_blocklist_match=True,
                moderator_approved=True,
                platform_release_authorized=True,
            )
            innocent = min_trust_protocol.assess_trace(
                source_account="synthetic-innocent-origin",
                verified_distinct_reports=args.required_reports,
                required_reports=args.required_reports,
                regulator_blocklist_match=False,
                moderator_approved=True,
                platform_release_authorized=True,
            )
            _print_json({
                "protocol": min_trust_protocol.protocol_id,
                "interoperable_with_reference": False,
                "valid_synthetic_case": valid.as_dict(),
                "innocent_control_case": innocent.as_dict(),
                "single_honest_role_scenarios": min_trust_protocol.single_honest_role_scenarios(required_reports=args.required_reports),
                "caveat": "illustrative policy simulation; not a cryptographic or formal security guarantee",
            })
        elif args.command == "traceback2019-tree-demo":
            _, _, tree = demo_tree()
            _print_json({"protocol": "traceback2019-synthetic-tree", "interoperable_with_reference": False, "tree": {"uid": tree.uid, "children": [{"uid": c.uid, "children": [{"uid": g.uid, "children": []} for g in c.children]} for c in tree.children]}})
        elif args.command == "traceback2019-benchmark":
            if args.message_size <= 0 or args.max_hops <= 0:
                raise ValueError("message-size and max-hops must be positive")
            result = {"protocol": "traceback2019-synthetic-path", "interoperable_with_reference": False, "message_size": args.message_size, "max_hops": args.max_hops, "records": benchmark_points(args.message_size, args.max_hops)}
            if args.out is not None:
                args.out.parent.mkdir(parents=True, exist_ok=True)
                args.out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
            _print_json(result)
        elif args.command == "traceback-reproduction":
            from .traceback_experiment import run_experiment, experiment_markdown
            msg_bytes = args.message.encode("utf-8")
            report = run_experiment(
                hops=args.hops,
                message=msg_bytes,
                scenario=args.scenario,
                adversarial_hop=args.adversarial_hop,
                enable_pki_extension=args.pki_extension,
            )
            if args.out is not None:
                args.out.parent.mkdir(parents=True, exist_ok=True)
                args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
            if args.markdown is not None:
                args.markdown.parent.mkdir(parents=True, exist_ok=True)
                args.markdown.write_text(experiment_markdown(report), encoding="utf-8")
            _print_json({
                "schema": report["schema"],
                "protocol": report["protocol"],
                "scenario": report["scenario"],
                "outcome": report["traceback_result"]["outcome"],
                "origin_reached": report["traceback_result"]["origin_reached"],
                "candidate_origin_account": report["traceback_result"]["candidate_origin_account"],
                "candidate_origin_device": report["traceback_result"]["candidate_origin_device"],
                "recovered_origin_account": report["traceback_result"]["recovered_origin_account"],
                "recovered_origin_device": report["traceback_result"]["recovered_origin_device"],
                "recovered_hops_count": report["traceback_result"]["recovered_hops_count"],
                "termination_reason": report["traceback_result"]["termination_reason"],
                "measurements": report["measurements"],
            })
        elif args.command == "merkle-verify":
            proof = load_json(args.proof)
            if args.entry_text is not None:
                entry = args.entry_text.encode("utf-8")
            else:
                entry = args.entry_file.read_bytes()
            is_valid = verify_inclusion(entry, proof)
            _print_json({"status": "VALID" if is_valid else "INVALID", "proof_valid": is_valid})
            if not is_valid:
                raise TransparencyError("Merkle inclusion proof did not verify")
    except (IntegrityError, AuthorizationError, TransparencyError, ValueError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc


if __name__ == "__main__":
    main()
