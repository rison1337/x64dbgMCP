"""Pure basic-block/edge reconstruction for enriched x64dbg trace events.

This module deliberately has no dependency on FastMCP, the HTTP bridge, or
process-global debugger state.  Keeping reconstruction pure makes the most
subtle coverage semantics testable with deterministic synthetic instruction
tapes, including interleaved threads and code that changes at the same RVA.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict
from typing import Any, Dict, Iterable, List, Optional, Tuple


RECONSTRUCTION_SCHEMA = "basic-block-edge-v2"


def _int_value(value: Any, default: int = 0) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    text = str(value or "").strip()
    if not text:
        return default
    try:
        return int(text, 0)
    except (TypeError, ValueError):
        try:
            return int(text, 16)
        except (TypeError, ValueError):
            return default


def _normalized_bytes(value: Any) -> str:
    text = re.sub(r"\s+", "", str(value or "")).lower()
    return text if text and len(text) % 2 == 0 and re.fullmatch(r"[0-9a-f]+", text) else ""


def _instruction_is_indirect(event: Dict[str, Any]) -> bool:
    if bool(event.get("indirect")):
        return True
    instruction = str(event.get("instruction") or "").strip().casefold()
    if not instruction:
        return False
    parts = instruction.split(None, 1)
    if not parts or parts[0] not in {
        "call",
        "callq",
        "jmp",
        "jmpq",
        "br",
        "blr",
    }:
        return False
    operand = parts[1].strip() if len(parts) > 1 else ""
    if not operand:
        return False
    # Memory operands and register operands are dynamic.  Plain numeric/symbol
    # destinations are direct even when x64dbg already resolved branchTarget.
    if any(marker in operand for marker in ("[", "]", "ptr ", "qword ", "dword ")):
        return True
    operand = operand.split(",", 1)[0].strip()
    return bool(
        re.fullmatch(
            r"(?:[re]?(?:ax|bx|cx|dx|si|di|sp|bp)|r(?:1[0-5]|[0-9])|"
            r"[abcd][lh]|[re]ip)",
            operand,
        )
    )


def _normalize_events(
    events: Iterable[Dict[str, Any]],
    module_base: int,
    module_size: int,
) -> List[Dict[str, Any]]:
    normalized: List[Dict[str, Any]] = []
    pending_exceptions: Dict[int, Dict[str, Any]] = {}
    for ordinal, raw in enumerate(events):
        if not isinstance(raw, dict):
            continue
        thread_id = max(0, _int_value(raw.get("threadId")))
        raw_exception = bool(
            raw.get("exceptionTransition")
            or raw.get("exception")
            or _int_value(raw.get("exceptionCode"))
        )
        ip = _int_value(raw.get("ip"))
        # Exception transitions are often observed in ntdll/ntdll's user
        # dispatcher while the logical handler is in the target image. Keep
        # the marker per thread even when the carrier instruction is outside
        # the requested module; it will be attached to the next in-range
        # instruction below.
        if raw_exception:
            pending_exceptions[thread_id] = dict(raw)
        if ip <= 0:
            continue
        if module_base and module_size and not (
            module_base <= ip < module_base + module_size
        ):
            continue
        carried_exception = pending_exceptions.pop(thread_id, None)
        event = dict(raw)
        if carried_exception is not None:
            event["exceptionTransition"] = True
            event.setdefault(
                "exceptionCode", carried_exception.get("exceptionCode")
            )
            event.setdefault(
                "exceptionFirstChance",
                carried_exception.get("exceptionFirstChance"),
            )
            event.setdefault(
                "exceptionAddress", carried_exception.get("exceptionAddress")
            )
        rva = _int_value(raw.get("rva"), -1)
        if rva < 0 or (rva == 0 and module_base and ip != module_base):
            rva = ip - module_base if module_base and ip >= module_base else ip
        size = max(0, _int_value(raw.get("instructionSize")))
        seq = _int_value(raw.get("seq"), ordinal + 1)
        instruction = str(event.get("instruction") or "").strip()
        is_return = bool(raw.get("isReturn")) or instruction.casefold().startswith(
            ("ret", "iret")
        )
        call = bool(raw.get("call"))
        branch = bool(raw.get("branch")) or call or is_return
        exception_transition = bool(
            event.get("exceptionTransition")
            or event.get("exception")
            or _int_value(event.get("exceptionCode"))
        )
        normalized.append(
            {
                **event,
                "_ordinal": ordinal,
                "_seq": seq,
                "_thread": thread_id,
                "_ip": ip,
                "_rva": rva,
                "_size": size,
                "_bytes": _normalized_bytes(event.get("bytes")),
                "_instruction": instruction,
                "_branch": branch,
                "_call": call,
                "_return": is_return,
                "_target": _int_value(raw.get("branchTarget")),
                "_indirect": _instruction_is_indirect(raw),
                "_exception": exception_transition,
            }
        )
    # The native ring is already ordered, but accepting shuffled synthetic or
    # persisted input deterministically makes the pure contract safer.
    normalized.sort(key=lambda item: (int(item["_seq"]), int(item["_ordinal"])))
    return normalized


def _block_fingerprint(events: List[Dict[str, Any]]) -> str:
    instructions = []
    for event in events:
        # Raw bytes are authoritative.  Decoder text is only a deterministic
        # fallback for old traces captured without bytes.
        material = event["_bytes"] or f"text:{event['_instruction'].casefold()}"
        instructions.append(
            {
                "rva": int(event["_rva"]),
                "size": int(event["_size"]),
                "material": material,
            }
        )
    encoded = json.dumps(
        instructions,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _edge_kind(previous: Dict[str, Any], current: Dict[str, Any]) -> str:
    terminal = previous["events"][-1]
    first = current["events"][0]
    next_ip = int(first["_ip"])
    target = int(terminal["_target"])
    fallthrough = int(terminal["_ip"]) + int(terminal["_size"])
    if bool(first["_exception"]) or bool(terminal["_exception"]):
        return "exception"
    if bool(terminal["_return"]):
        return "return"
    if bool(terminal["_call"]):
        return "indirect-call" if bool(terminal["_indirect"]) else "call"
    if bool(terminal["_branch"]):
        if target and next_ip == target:
            return "indirect-taken" if bool(terminal["_indirect"]) else "taken"
        if terminal["_size"] and next_ip == fallthrough:
            return "not-taken"
        return "indirect-observed" if bool(terminal["_indirect"]) else "branch-observed"
    if terminal["_size"] and next_ip == fallthrough:
        return "fallthrough"
    return "discontinuity"


def reconstruct_basic_block_coverage(
    events: Iterable[Dict[str, Any]],
    module_base: int,
    module_size: int,
    image_identity: str,
    limit: int,
) -> Dict[str, Any]:
    """Reconstruct execution-counted, version-aware blocks and directed edges.

    ``hits`` counts block executions, not instructions.  ``instructionHits``
    preserves the latter metric.  Blocks at the same RVA whose captured bytes
    differ receive distinct stable keys and are reported as self-modifying.
    """

    identity = str(image_identity or "runtime").strip().lower()
    normalized = _normalize_events(events, int(module_base), int(module_size))

    instances: List[Dict[str, Any]] = []
    thread_state: Dict[int, Dict[str, Any]] = {}

    def finish(thread_id: int) -> Optional[int]:
        state = thread_state.get(thread_id)
        current = list((state or {}).get("current") or [])
        if not current:
            return None
        instance = {
            "events": current,
            "threadId": thread_id,
            "startRva": int(current[0]["_rva"]),
            "endRva": int(current[-1]["_rva"]),
            "fingerprint": _block_fingerprint(current),
        }
        instances.append(instance)
        index = len(instances) - 1
        state["current"] = []
        state["lastInstance"] = index
        return index

    for event in normalized:
        thread_id = int(event["_thread"])
        state = thread_state.setdefault(
            thread_id, {"current": [], "lastInstance": None}
        )
        current: List[Dict[str, Any]] = state["current"]
        start_new = not current
        if current:
            previous = current[-1]
            expected = int(previous["_ip"]) + int(previous["_size"])
            start_new = bool(
                previous["_branch"]
                or previous["_call"]
                or previous["_return"]
                or previous["_exception"]
                or not previous["_size"]
                or int(event["_ip"]) != expected
                or event.get("blockStart")
            )
        if start_new:
            source_index = finish(thread_id) if current else state.get("lastInstance")
            state["current"] = [event]
            # Final edges are reconstructed per thread after every destination
            # block has been closed and fingerprinted.
            state["incomingSource"] = (
                int(source_index) if source_index is not None else None
            )
        else:
            current.append(event)

        state.pop("incomingSource", None)

    for thread_id in sorted(thread_state):
        finish(thread_id)

    corrected_transitions: List[Tuple[int, int, str, int, bool]] = []
    # Rebuild transitions per thread from final instance order.  This is both
    # simpler and correct for interleaved traces.
    by_thread: Dict[int, List[int]] = defaultdict(list)
    for index, item in enumerate(instances):
        by_thread[int(item["threadId"])].append(index)
    for indexes in by_thread.values():
        indexes.sort(key=lambda idx: int(instances[idx]["events"][0]["_seq"]))
        for source_index, destination_index in zip(indexes, indexes[1:]):
            source = instances[source_index]
            destination = instances[destination_index]
            terminal = source["events"][-1]
            corrected_transitions.append(
                (
                    source_index,
                    destination_index,
                    _edge_kind(source, destination),
                    int(terminal["_target"]),
                    bool(terminal["_indirect"]),
                )
            )
    transitions = corrected_transitions

    versions_by_rva: Dict[int, List[str]] = defaultdict(list)
    for item in instances:
        rva = int(item["startRva"])
        fingerprint = str(item["fingerprint"])
        if fingerprint not in versions_by_rva[rva]:
            versions_by_rva[rva].append(fingerprint)
    for fingerprints in versions_by_rva.values():
        fingerprints.sort()

    grouped: Dict[Tuple[int, str], Dict[str, Any]] = {}
    instance_keys: Dict[int, str] = {}
    for index, instance in enumerate(instances):
        start_rva = int(instance["startRva"])
        fingerprint = str(instance["fingerprint"])
        versions = versions_by_rva[start_rva]
        version = versions.index(fingerprint) + 1
        base_key = f"{identity}:{start_rva:x}"
        stable_key = (
            base_key
            if len(versions) == 1
            else f"{base_key}:v:{fingerprint[:16]}"
        )
        instance_keys[index] = stable_key
        group_key = (start_rva, fingerprint)
        group = grouped.get(group_key)
        instruction_count = len(instance["events"])
        if group is None:
            group = {
                "id": stable_key,
                "stableKey": stable_key,
                "baseStableKey": base_key,
                "startRva": f"0x{start_rva:x}",
                "endRva": f"0x{int(instance['endRva']):x}",
                "hits": 0,
                "instructionHits": 0,
                "instructionCount": 0,
                "threadIds": set(),
                "firstSeq": int(instance["events"][0]["_seq"]),
                "lastSeq": int(instance["events"][-1]["_seq"]),
                "codeSha256": fingerprint.upper(),
                "codeVersion": version,
                "versionCountAtRva": len(versions),
                "selfModified": len(versions) > 1,
            }
            grouped[group_key] = group
        group["hits"] += 1
        group["instructionHits"] += instruction_count
        group["instructionCount"] = max(
            int(group["instructionCount"]), instruction_count
        )
        group["threadIds"].add(int(instance["threadId"]))
        group["firstSeq"] = min(
            int(group["firstSeq"]), int(instance["events"][0]["_seq"])
        )
        group["lastSeq"] = max(
            int(group["lastSeq"]), int(instance["events"][-1]["_seq"])
        )
        group["endRva"] = f"0x{max(int(str(group['endRva']), 16), int(instance['endRva'])):x}"

    edge_map: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
    for source_index, destination_index, kind, target, indirect in transitions:
        source_key = instance_keys[source_index]
        destination_key = instance_keys[destination_index]
        edge_key = (source_key, destination_key, kind)
        edge = edge_map.setdefault(
            edge_key,
            {
                "from": source_key,
                "to": destination_key,
                "hits": 0,
                "branchTargets": set(),
                "kind": kind,
                "indirect": bool(indirect),
            },
        )
        edge["hits"] += 1
        if target:
            edge["branchTargets"].add(f"0x{target:x}")

    blocks: List[Dict[str, Any]] = []
    for group in sorted(
        grouped.values(),
        key=lambda item: (
            int(str(item["startRva"]), 16),
            int(item["codeVersion"]),
            str(item["stableKey"]),
        ),
    ):
        block = dict(group)
        block["threadIds"] = sorted(block["threadIds"])
        blocks.append(block)
    edges: List[Dict[str, Any]] = []
    for raw in sorted(
        edge_map.values(),
        key=lambda item: (str(item["from"]), str(item["to"]), str(item["kind"])),
    ):
        edge = dict(raw)
        edge["branchTargets"] = sorted(edge["branchTargets"])
        edges.append(edge)

    capped = max(1, min(int(limit), 5000))
    returned_blocks = blocks[:capped]
    returned_keys = {str(item["stableKey"]) for item in returned_blocks}
    returned_edges = [
        item
        for item in edges
        if str(item["from"]) in returned_keys and str(item["to"]) in returned_keys
    ][: max(1, capped * 4)]
    self_modifying_rvas = [
        f"0x{rva:x}"
        for rva, fingerprints in sorted(versions_by_rva.items())
        if len(fingerprints) > 1
    ]
    covered_addresses = {int(item["_ip"]) for item in normalized}
    covered_versions = {
        (
            int(item["_rva"]),
            item["_bytes"] or f"text:{item['_instruction'].casefold()}",
        )
        for item in normalized
    }
    return {
        # Keep the historical model name for compatibility while publishing
        # the corrected reconstruction schema explicitly.
        "coverageModel": "basic-block-edge-v1",
        "reconstructionSchema": RECONSTRUCTION_SCHEMA,
        "stableIdentity": identity,
        "blocks": returned_blocks,
        "edges": returned_edges,
        "blockCount": len(blocks),
        "edgeCount": len(edges),
        "returnedBlockCount": len(returned_blocks),
        "returnedEdgeCount": len(returned_edges),
        "truncated": len(returned_blocks) < len(blocks)
        or len(returned_edges) < len(edges),
        "coveredInstructions": len(covered_addresses),
        "coveredInstructionVersions": len(covered_versions),
        "executedBlockHits": sum(int(item["hits"]) for item in blocks),
        "executedInstructionHits": sum(
            int(item["instructionHits"]) for item in blocks
        ),
        "executedEdgeHits": sum(int(item["hits"]) for item in edges),
        "eventCount": len(normalized),
        "threadCount": len({int(item["_thread"]) for item in normalized}),
        "versionedBlockCount": sum(
            1 for item in blocks if bool(item.get("selfModified"))
        ),
        "selfModifyingRvas": self_modifying_rvas,
        "indirectEdgeCount": sum(
            1 for item in edges if bool(item.get("indirect"))
        ),
        "exceptionEdgeCount": sum(
            1 for item in edges if item.get("kind") == "exception"
        ),
    }


__all__ = ["RECONSTRUCTION_SCHEMA", "reconstruct_basic_block_coverage"]
