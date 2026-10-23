"""Validation and reporting for synthetic, explicit forwarding event graphs.

This module does not infer an absent forwarding chain. It only follows event
edges explicitly present in the supplied data and preserves source-time labels.
"""
from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime
from typing import Any

_ALLOWED_TYPES = {"ORIGIN", "FORWARD", "DELIVER", "REPORT"}
_ALLOWED_EVIDENCE_CLASSES = {"synthetic", "observed", "provider_attested", "protocol_verified", "inferred", "unknown"}
_MAX_EVENTS = 100_000
_MAX_ID_LENGTH = 2048


class TraceGraphError(ValueError):
    """Raised for malformed or contradictory event graphs."""


def _parse_rfc3339(value: str, event_id: str) -> datetime:
    if not isinstance(value, str):
        raise TraceGraphError(f"Event {event_id}: timestamp must be a string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise TraceGraphError(f"Event {event_id}: invalid RFC 3339 timestamp") from exc
    if parsed.tzinfo is None:
        raise TraceGraphError(f"Event {event_id}: timestamp must include a timezone")
    return parsed


def validate_events(events: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    if not isinstance(events, list) or not events:
        raise TraceGraphError("events must be a non-empty list")
    if len(events) > _MAX_EVENTS:
        raise TraceGraphError(f"events exceed the safety limit of {_MAX_EVENTS}")
    by_id: dict[str, dict[str, Any]] = {}
    for event in events:
        if not isinstance(event, dict):
            raise TraceGraphError("every event must be an object")
        event_id = event.get("event_id")
        if not isinstance(event_id, str) or not event_id or len(event_id) > _MAX_ID_LENGTH:
            raise TraceGraphError("every event requires a non-empty event_id of bounded length")
        if event_id in by_id:
            raise TraceGraphError(f"duplicate event_id: {event_id}")
        kind = event.get("event_type")
        if kind not in _ALLOWED_TYPES:
            raise TraceGraphError(f"Event {event_id}: unsupported event_type {kind!r}")
        actor = event.get("actor_id")
        if not isinstance(actor, str) or not actor or len(actor) > _MAX_ID_LENGTH:
            raise TraceGraphError(f"Event {event_id}: actor_id is required and must be bounded")
        content_ref = event.get("content_ref")
        if not isinstance(content_ref, str) or not content_ref or len(content_ref) > _MAX_ID_LENGTH:
            raise TraceGraphError(f"Event {event_id}: content_ref is required and must be bounded")
        if not isinstance(event.get("time_source"), str) or not event["time_source"]:
            raise TraceGraphError(f"Event {event_id}: time_source is required")
        if event.get("evidence_class") not in _ALLOWED_EVIDENCE_CLASSES:
            raise TraceGraphError(f"Event {event_id}: evidence_class is required and must be recognized")
        _parse_rfc3339(event.get("timestamp"), event_id)
        parent = event.get("parent_event_id")
        if parent is not None and not isinstance(parent, str):
            raise TraceGraphError(f"Event {event_id}: parent_event_id must be string or null")
        by_id[event_id] = event

    for event in events:
        parent = event.get("parent_event_id")
        if parent is not None and parent not in by_id:
            raise TraceGraphError(f"Event {event['event_id']}: missing parent event {parent}")
        if event["event_type"] == "ORIGIN" and parent is not None:
            raise TraceGraphError(f"Origin event {event['event_id']} cannot have a parent")
        if event["event_type"] != "ORIGIN" and parent is None:
            raise TraceGraphError(f"Non-origin event {event['event_id']} must name its parent")
        if parent is not None and by_id[parent].get("content_ref") != event.get("content_ref"):
            raise TraceGraphError(f"Event {event['event_id']}: parent content_ref differs")

    # Iterative parent-pointer traversal avoids recursion-depth failure on long
    # evidence chains. Each node has at most one parent, so three-color DFS is
    # unnecessary: mark each walked chain and detect a repeated node locally.
    done: set[str] = set()
    for start_id in by_id:
        if start_id in done:
            continue
        chain: list[str] = []
        active: set[str] = set()
        cursor: str | None = start_id
        while cursor is not None and cursor not in done:
            if cursor in active:
                raise TraceGraphError(f"cycle detected at event {cursor}")
            active.add(cursor)
            chain.append(cursor)
            cursor = by_id[cursor].get("parent_event_id")
        done.update(chain)

    # An origin event must exist for every content_ref; parent-graph validity alone
    # does not imply an observed origin.
    origins_by_content: dict[str, int] = defaultdict(int)
    for event in events:
        if event["event_type"] == "ORIGIN":
            origins_by_content[event["content_ref"]] += 1
    for content_ref in {e["content_ref"] for e in events}:
        if origins_by_content[content_ref] != 1:
            raise TraceGraphError(
                f"content_ref {content_ref} must have exactly one ORIGIN event; "
                f"found {origins_by_content[content_ref]}"
            )
    return by_id


def _event_sort_key(event: dict[str, Any]) -> tuple[datetime, str]:
    # Sort by parsed instants (not lexicographic local timestamp strings) for a
    # readable report only; timestamps are not assumed to be authoritative.
    return (_parse_rfc3339(event["timestamp"], event["event_id"]), event["event_id"])


def build_trace_report(
    events: list[dict[str, Any]],
    reported_event_id: str,
    mode: str = "ORIGIN_ONLY",
) -> dict[str, Any]:
    """Build a disclosure-limited synthetic report.

    ORIGIN_ONLY is the default. PATH and TREE are explicitly separate modes;
    the caller must choose them rather than receiving every available edge.
    This is a graph demonstration, not a cryptographic tracing protocol.
    """
    if not isinstance(mode, str):
        raise TraceGraphError("disclosure mode must be a string")
    mode = mode.upper()
    if mode not in {"ORIGIN_ONLY", "PATH", "TREE"}:
        raise TraceGraphError(f"unsupported disclosure mode: {mode}")
    by_id = validate_events(events)
    if reported_event_id not in by_id:
        raise TraceGraphError(f"reported_event_id not found: {reported_event_id}")
    target = by_id[reported_event_id]
    if target["event_type"] != "REPORT":
        raise TraceGraphError("reported_event_id must refer to a REPORT event in v0.1")
    content_ref = target["content_ref"]
    ancestors: list[dict[str, Any]] = []
    cursor: str | None = reported_event_id
    while cursor is not None:
        node = by_id[cursor]
        ancestors.append(node)
        cursor = node.get("parent_event_id")
    path = list(reversed(ancestors))
    origin = path[0]

    def present(event: dict[str, Any]) -> dict[str, Any]:
        return {
            "event_id": event["event_id"],
            "event_type": event["event_type"],
            "actor_id": event["actor_id"],
            "timestamp": event["timestamp"],
            "time_source": event["time_source"],
            "parent_event_id": event.get("parent_event_id"),
            "content_ref": event["content_ref"],
            "evidence_class": event.get("evidence_class", "unspecified"),
        }

    report: dict[str, Any] = {
        "report_version": "0.1",
        "mode": mode,
        "case_disclaimer": (
            "Synthetic data only. This report demonstrates graph traversal; it is not a "
            "cryptographic traceback protocol, WhatsApp integration, or real-world identity proof."
        ),
        "reported_event_id": reported_event_id,
        "content_ref": content_ref,
        "first_originator_candidate": {
            "actor_id": origin["actor_id"],
            "basis": "explicit synthetic ORIGIN event at the root of the supplied parent graph",
            "status": "synthetic-only; not an identity claim",
            "event": present(origin),
        },
        "disclosure_notice": {
            "ORIGIN_ONLY": "Only the synthetic origin candidate and origin event are disclosed; path and tree fields are omitted.",
            "PATH": "The synthetic origin-to-reported-event path is disclosed; sibling branches are omitted.",
            "TREE": "All linked events in the supplied synthetic forwarding tree are disclosed.",
        }[mode],
        "timestamp_warning": (
            "Timestamps are copied from the input and labelled with their source. Their order is "
            "not proof of wall-clock order unless corroborated by a trusted source."
        ),
    }

    if mode == "PATH":
        report["reported_path_oldest_to_newest"] = [present(e) for e in path]
    elif mode == "TREE":
        children: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for event in events:
            parent = event.get("parent_event_id")
            if parent is not None:
                children[parent].append(event)
        subtree: list[dict[str, Any]] = []
        queue = deque([origin["event_id"]])
        seen: set[str] = set()
        while queue:
            current = queue.popleft()
            if current in seen:
                continue
            seen.add(current)
            node = by_id[current]
            if node.get("content_ref") == content_ref:
                subtree.append(node)
                for child in children.get(current, []):
                    queue.append(child["event_id"])
        report["forwarding_tree_in_supplied_dataset"] = [present(e) for e in sorted(subtree, key=_event_sort_key)]
    return report
