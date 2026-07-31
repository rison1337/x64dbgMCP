import importlib.util
import hashlib
import io
import json
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "tools" / "run_live_release_matrix.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("x64dbg_live_release_matrix_tests", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    # dataclasses resolves postponed annotations through sys.modules.
    import sys

    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class _FakeProcess:
    def __init__(self, pid=1234, returncode=None):
        self.pid = pid
        self.returncode = returncode
        self.killed = False

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        if self.returncode is None:
            raise subprocess.TimeoutExpired("fake", timeout)
        return self.returncode

    def kill(self):
        self.killed = True
        self.returncode = -9


class _ExceptionPolicyBridge:
    """Deterministic state machine for the four native policy live adapters."""

    EXACT = 0xE0424242
    MASKED = 0xE0429999
    WILDCARD = 0xA1234567

    def __init__(self):
        self.bridge_instance_id = "exception-policy-test-bridge"
        self.generation = 0
        self.session_id = ""
        self.mode = ""
        self.policy_version = 0
        self.policy = self._fresh_policy()
        self.history = []
        self.history_next_seq = 1
        self.event_seq = 100
        self.exit_code = None
        self.paused_exception = None

    @staticmethod
    def _fresh_policy():
        return {
            "enabled": False,
            "version": 0,
            "firstChanceDefault": "pause",
            "secondChanceDefault": "pause",
            "ruleCount": 0,
            "rules": [],
        }

    def _meta(self):
        return {
            "bridgeInstanceId": self.bridge_instance_id,
            "sessionId": self.session_id,
            "sessionGeneration": self.generation,
            "eventSeq": self.event_seq,
            "processId": 4000 + self.generation,
        }

    @staticmethod
    def _copy_policy(policy):
        return json.loads(json.dumps(policy))

    def InitDebuggee(self, _path, **kwargs):
        self.generation += 1
        self.session_id = f"exception-session-{self.generation}"
        self.mode = kwargs["arguments"][0]
        self.policy_version = 0
        self.policy = self._fresh_policy()
        self.history = []
        self.history_next_seq = 1
        self.event_seq += 10
        self.exit_code = None
        self.paused_exception = None
        return {
            "ok": True,
            "state": {
                "session": {
                    "sessionId": self.session_id,
                    "generation": self.generation,
                    "eventSeq": self.event_seq,
                    "processId": 4000 + self.generation,
                }
            },
        }

    def RunUntil(self, **_kwargs):
        return {
            "ok": True,
            "session": {
                "sessionId": self.session_id,
                "generation": self.generation,
                "eventSeq": self.event_seq,
                "processId": 4000 + self.generation,
            },
        }

    def SetExceptionPolicy(
        self,
        rules_json,
        *,
        enabled,
        first_chance_default,
        second_chance_default,
        replace,
    ):
        raw_rules = json.loads(rules_json)
        rules = []
        for index, raw in enumerate(raw_rules, 1):
            raw_codes = raw.get("codes", raw.get("code", "*"))
            codes = raw_codes if isinstance(raw_codes, list) else [raw_codes]
            rules.append(
                {
                    "ruleId": str(raw.get("ruleId") or f"rule-{index}"),
                    "codes": [str(item).casefold() for item in codes],
                    "chance": str(raw.get("chance") or "any").casefold(),
                    "action": str(raw.get("action") or "pause").casefold(),
                    "priority": int(raw.get("priority", 0)),
                    "enabled": bool(raw.get("enabled", True)),
                    "insertionOrder": index,
                }
            )
        if replace:
            self.policy["rules"] = list(rules)
        else:
            self.policy["rules"].extend(rules)
        self.policy.update(
            {
                "enabled": bool(enabled),
                "firstChanceDefault": first_chance_default,
                "secondChanceDefault": second_chance_default,
            }
        )
        self.policy_version += 1
        self.policy["version"] = self.policy_version
        self.policy["ruleCount"] = len(self.policy["rules"])
        return {
            "ok": True,
            "policy": self._copy_policy(self.policy),
            "meta": self._meta(),
        }

    def ClearExceptionHistory(self):
        cleared = len(self.history)
        self.history = []
        return {"ok": True, "cleared": cleared}

    def ClearExceptionPolicy(self, clear_history=False):
        history_cleared = len(self.history) if clear_history else 0
        self.policy_version += 1
        self.policy = self._fresh_policy()
        self.policy["version"] = self.policy_version
        if clear_history:
            self.history = []
        return {
            "ok": True,
            "historyCleared": history_cleared,
            "policy": self._copy_policy(self.policy),
            "meta": self._meta(),
        }

    def GetExceptionPolicy(self):
        return {
            "ok": True,
            "policy": self._copy_policy(self.policy),
            "meta": self._meta(),
        }

    def _record(
        self,
        code,
        *,
        first,
        action,
        rule_id="",
        selector="",
        source=None,
        auto=False,
        command="",
        submitted=False,
        status="paused",
        disposition="default",
    ):
        seq = self.history_next_seq
        self.history_next_seq += 1
        self.event_seq += 1
        requested = action
        applied = action if auto and submitted else "none"
        outcome = "applied" if auto and submitted else "paused"
        continuation_source = "policy" if auto else "none"
        record = {
            "historySeq": seq,
            "seq": seq,
            "eventSeq": self.event_seq,
            "bridgeInstanceId": self.bridge_instance_id,
            "sessionId": self.session_id,
            "sessionGeneration": self.generation,
            "policyVersion": 1,
            "tickMs": 1000 + seq,
            "lastUpdateMs": 2000 + seq,
            "timestamp100ns": 10_000_000 + seq,
            "lastUpdateTimestamp100ns": 20_000_000 + seq,
            "processId": 4000 + self.generation,
            "threadId": 5000 + seq,
            "exceptionCode": f"0x{code:08x}",
            "chance": "first" if first else "second",
            "firstChance": bool(first),
            "address": "0x401000",
            "ip": "0x401000",
            "action": action,
            "source": source or (
                "rule"
                if rule_id
                else "first_chance_default" if first else "second_chance_default"
            ),
            "ruleId": rule_id,
            "matchedSelector": selector,
            "autoContinue": bool(auto),
            "continuationSource": continuation_source,
            "continuationClaimed": bool(auto),
            "commandSubmitted": bool(submitted),
            "dispositionSubmitted": bool(submitted),
            "resumeRequested": bool(auto),
            "resumeSubmitted": bool(auto and submitted),
            "command": command,
            "status": status,
            "disposition": disposition,
            "requestedDisposition": requested,
            "appliedDisposition": applied,
            "outcome": outcome,
        }
        self.history.append(record)
        return record

    def _rule(self, rule_id):
        return next(item for item in self.policy["rules"] if item["ruleId"] == rule_id)

    @staticmethod
    def _selector_match(selector, code):
        selector = str(selector).casefold()
        if selector == "*":
            return (0, 0)
        if "/" in selector:
            value_text, mask_text = selector.split("/", 1)
            value = int(value_text, 0)
            mask = int(mask_text, 0)
            if (code & mask) == (value & mask):
                return (1, int(mask).bit_count())
            return None
        return (2, 32) if code == int(selector, 0) else None

    def _decision(self, code, first):
        candidates = []
        for index, rule in enumerate(self.policy["rules"]):
            if not rule.get("enabled", True):
                continue
            chance = str(rule.get("chance") or "any")
            if chance == "first" and not first:
                continue
            if chance == "second" and first:
                continue
            for selector in rule.get("codes") or []:
                specificity = self._selector_match(selector, code)
                if specificity is None:
                    continue
                candidates.append(
                    (
                        specificity[0],
                        specificity[1],
                        int(rule.get("priority", 0)),
                        -int(rule.get("insertionOrder", index + 1)),
                        str(rule.get("ruleId") or ""),
                        rule,
                        str(selector),
                    )
                )
        if candidates:
            _kind, _bits, _priority, _order, _id, rule, selector = max(
                candidates, key=lambda item: item[:5]
            )
            return {
                "action": rule["action"],
                "source": "rule",
                "ruleId": rule["ruleId"],
                "selector": selector,
            }
        return {
            "action": self.policy[
                "firstChanceDefault" if first else "secondChanceDefault"
            ],
            "source": "first_chance_default" if first else "second_chance_default",
            "ruleId": "",
            "selector": "",
        }

    def _record_decision(self, code, first, decision):
        action = decision["action"]
        auto = action in {"handled", "not_handled"}
        return self._record(
            code,
            first=first,
            action=action,
            rule_id=decision["ruleId"],
            selector=decision["selector"],
            source=decision["source"],
            auto=auto,
            command=("con" if action == "handled" else "con 1") if auto else "",
            submitted=auto,
            status="auto_resumed" if auto else "paused",
            disposition=action if auto else "default",
        )

    def DebugRun(self):
        if self.paused_exception is not None:
            if self.paused_exception.get("continuationClaimed"):
                self.exit_code = 0
                self.paused_exception = None
            return "Execution resumed"

        if self.mode == "policy-sequence":
            for code in (self.EXACT, self.MASKED, self.WILDCARD):
                decision = self._decision(code, True)
                record = self._record_decision(code, True, decision)
                if decision["action"] == "pause":
                    self.paused_exception = record
                    return "Execution resumed"
                if decision["action"] != "not_handled":
                    self.exit_code = 69
                    return "Execution resumed"
            self.exit_code = 0
            return "Execution resumed"

        if self.mode == "unhandled":
            first_decision = self._decision(self.EXACT, True)
            first_record = self._record_decision(self.EXACT, True, first_decision)
            if first_decision["action"] == "pause":
                self.paused_exception = first_record
                return "Execution resumed"
            second_decision = self._decision(self.EXACT, False)
            second_record = self._record_decision(self.EXACT, False, second_decision)
            if second_decision["action"] == "pause":
                self.paused_exception = second_record
            else:
                self.exit_code = self.EXACT
            return "Execution resumed"

        decision = self._decision(self.EXACT, True)
        record = self._record_decision(self.EXACT, True, decision)
        if decision["action"] == "pause":
            self.paused_exception = record
        elif decision["action"] == "not_handled":
            self.exit_code = 0
        else:
            self.exit_code = 70 if self.mode == "first-chance" else 68
        return "Execution resumed"

    def WaitForExit(self, **_kwargs):
        return {
            "exited": self.exit_code is not None,
            "session": {
                "sessionId": self.session_id,
                "generation": self.generation,
                "exitCode": self.exit_code,
            },
        }

    def WaitForPause(self, **_kwargs):
        record = self.paused_exception or {}
        return {
            "paused": bool(record),
            "eventSeq": record.get("eventSeq", 0),
            "stopReason": "exception" if record else "",
            "session": {
                "sessionId": self.session_id,
                "generation": self.generation,
                "eventSeq": record.get("eventSeq", 0),
                "exceptionEventSeq": record.get("eventSeq", 0),
                "exceptionCode": record.get("exceptionCode", "0x0"),
                "exceptionFirstChance": record.get("firstChance", False),
                "stopReason": "exception" if record else "",
            },
        }

    def ContinueException(self, *, disposition, expected_event_seq, resume):
        del resume
        record = self.paused_exception
        if not record or record["eventSeq"] != expected_event_seq:
            return {"ok": False, "errorCode": "STALE_EXCEPTION_EVENT"}
        if record["continuationClaimed"]:
            return {"ok": False, "errorCode": "EXCEPTION_ALREADY_CLAIMED"}
        record.update(
            {
                "continuationClaimed": True,
                "commandSubmitted": True,
                "dispositionSubmitted": True,
                "resumeRequested": False,
                "resumeSubmitted": False,
                "command": "con 1" if disposition == "pass" else "con",
                "continuationSource": "manual",
                "status": "disposition_applied",
                "disposition": "not_handled" if disposition == "pass" else "handled",
                "requestedDisposition": (
                    "not_handled" if disposition == "pass" else "handled"
                ),
                "appliedDisposition": (
                    "not_handled" if disposition == "pass" else "handled"
                ),
                "outcome": "applied",
                "lastUpdateMs": record["lastUpdateMs"] + 1,
                "lastUpdateTimestamp100ns": record["lastUpdateTimestamp100ns"] + 1,
            }
        )
        return {"ok": True, "eventSeq": expected_event_seq}

    def GetExceptionHistory(self, after_seq=0, limit=100):
        available = [item for item in self.history if item["historySeq"] > after_seq]
        records = available[:limit]
        next_after = records[-1]["historySeq"] if records else after_seq
        oldest = self.history[0]["historySeq"] if self.history else self.history_next_seq
        latest = self.history_next_seq - 1 if self.history_next_seq > 1 else 0
        return {
            "ok": True,
            "history": [dict(item) for item in records],
            "afterSeq": after_seq,
            "nextAfterSeq": next_after,
            "limit": limit,
            "returned": len(records),
            "hasMore": len(available) > len(records),
            "oldestAvailableSeq": oldest,
            "latestSeq": latest,
            "dropped": 0,
            "cursorTruncated": False,
            "meta": self._meta(),
        }


class _EvidenceBridge:
    """Stateful x64dbg DB double for the strict evidence lifecycle."""

    def __init__(self):
        self.current_path = Path()
        self.base = 0
        self.init_count = 0
        self.labels = {}
        self.comments = {}
        self.bookmarks = {}
        self.functions = {}
        self.delete_calls = []
        self.import_calls = []

    @property
    def module_name(self):
        return self.current_path.name

    @property
    def target_rva(self):
        return 0x1020

    def _rehydrate_stale_database(self):
        rva = self.target_rva
        self.labels = {rva: {"text": "stale-label", "manual": True}}
        self.comments = {rva: {"text": "stale-comment", "manual": True}}
        self.bookmarks = {rva: {"manual": True}}
        self.functions = {rva + 0x20: {"rvaEnd": rva + 0x2F, "manual": True}}

    def InitDebuggee(self, path, **_kwargs):
        self.init_count += 1
        self.current_path = Path(path).resolve(strict=False)
        self.base = 0x140000000 if self.init_count == 1 else 0x180000000
        # Models x64dbg restoring the same-hash database on every load.
        self._rehydrate_stale_database()
        return {"ok": True}

    @staticmethod
    def RunUntil(**_kwargs):
        return {"ok": True}

    @staticmethod
    def DebugStop():
        return {"ok": True}

    def GetModuleList(self):
        return {
            "modules": [
                {
                    "name": self.module_name,
                    "path": str(self.current_path),
                    "base": hex(self.base),
                    "entry": hex(self.base + 0x1000),
                    "size": "0x4000",
                }
            ]
        }

    def _records(self, source, *, functions=False):
        records = []
        for rva, value in sorted(source.items()):
            record = {"module": self.module_name, "manual": value["manual"]}
            if functions:
                record.update(
                    {
                        "rvaStart": hex(rva),
                        "rvaEnd": hex(value["rvaEnd"]),
                        "instructionCount": 0,
                    }
                )
            else:
                record["rva"] = hex(rva)
                if "text" in value:
                    record["text"] = value["text"]
            records.append(record)
        return records

    @staticmethod
    def _page(records, field, offset, limit):
        page = records[offset : offset + limit]
        next_offset = offset + len(page)
        has_more = next_offset < len(records)
        return {
            "ok": True,
            field: page,
            "count": len(records),
            "offset": offset,
            "returned": len(page),
            "hasMore": has_more,
            "nextOffset": next_offset if has_more else None,
        }

    def LabelList(self):
        records = self._records(self.labels)
        return {"count": len(records), "labels": records}

    def CommentList(self, module="", offset=0, limit=500):
        self._assert_module(module)
        return self._page(self._records(self.comments), "comments", offset, limit)

    def BookmarkList(self, module="", offset=0, limit=500):
        self._assert_module(module)
        return self._page(self._records(self.bookmarks), "bookmarks", offset, limit)

    def FunctionList(self, module="", offset=0, limit=500):
        self._assert_module(module)
        return self._page(
            self._records(self.functions, functions=True), "functions", offset, limit
        )

    def _assert_module(self, module):
        if module.casefold() != self.module_name.casefold():
            raise AssertionError((module, self.module_name))

    def _delete(self, kind, source, address):
        rva = int(str(address), 0) - self.base
        existed = rva in source
        if existed:
            del source[rva]
        self.delete_calls.append((self.init_count, kind, rva, existed))
        return {"ok": True, "success": existed, "deleted": existed}

    def LabelDelete(self, address):
        return self._delete("label", self.labels, address)

    def CommentDelete(self, address):
        return self._delete("comment", self.comments, address)

    def BookmarkDelete(self, address):
        return self._delete("bookmark", self.bookmarks, address)

    def FunctionDelete(self, address):
        return self._delete("function", self.functions, address)

    def LabelSet(self, address, text, manual=True):
        rva = int(str(address), 0) - self.base
        if rva in self.labels:
            return {"ok": True, "success": False}
        self.labels[rva] = {"text": text, "manual": manual}
        return {"success": True, "address": address, "label": text, "manual": manual}

    def CommentSet(self, address, text, manual=True):
        rva = int(str(address), 0) - self.base
        if rva in self.comments:
            return {"ok": True, "success": False}
        self.comments[rva] = {"text": text, "manual": manual}
        return {"success": True, "address": address, "manual": manual}

    def BookmarkSet(self, address, manual=True):
        rva = int(str(address), 0) - self.base
        if rva in self.bookmarks:
            return {"ok": True, "success": False}
        self.bookmarks[rva] = {"manual": manual}
        return {"ok": True, "success": True, "address": address, "manual": manual}

    def LabelGet(self, address):
        rva = int(str(address), 0) - self.base
        item = self.labels.get(rva)
        return {
            "address": address,
            "found": item is not None,
            "label": item["text"] if item else "",
        }

    def CommentGet(self, address):
        rva = int(str(address), 0) - self.base
        item = self.comments.get(rva)
        return {
            "address": address,
            "found": item is not None,
            "comment": item["text"] if item else "",
        }

    def BookmarkGet(self, address):
        rva = int(str(address), 0) - self.base
        item = self.bookmarks.get(rva)
        payload = {"ok": True, "address": address, "found": item is not None}
        if item:
            payload.update({"module": self.module_name, "rva": hex(rva), **item})
        return payload

    def ExportAnalysisEvidence(
        self, output_path, overwrite=False, include_breakpoints=True, include_patches=True
    ):
        if overwrite or include_breakpoints or include_patches:
            raise AssertionError("The adapter must explicitly disable transient evidence.")
        source_hash = hashlib.sha256(self.current_path.read_bytes()).hexdigest().upper()
        evidence = {
            "labels": [
                {"rva": hex(rva), "text": value["text"], "manual": value["manual"]}
                for rva, value in sorted(self.labels.items())
            ],
            "comments": [
                {"rva": hex(rva), "text": value["text"], "manual": value["manual"]}
                for rva, value in sorted(self.comments.items())
            ],
            "bookmarks": [
                {"rva": hex(rva), "manual": value["manual"]}
                for rva, value in sorted(self.bookmarks.items())
            ],
            "functions": [],
            "breakpoints": [],
            "patches": [],
            "nativeTraceHits": [],
            "apiCallsites": [],
        }
        counts = {key: len(value) for key, value in evidence.items()}
        document = {
            "schema": "x64dbg-mcp-evidence",
            "version": 1,
            "image": {
                "name": self.module_name,
                "sha256": source_hash,
                "arch": "x64",
                "runtimeImageBase": hex(self.base),
            },
            "evidence": evidence,
            "counts": counts,
        }
        Path(output_path).write_text(
            json.dumps(document, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        return {"ok": True, "document": document, "output": output_path}

    def _import_record(self, kind, item, address, *, operation=None, reason=None):
        result = {
            "kind": kind,
            "rva": item["rva"],
            "address": address,
            "manual": item["manual"],
        }
        if kind in {"label", "comment"}:
            result["text"] = item["text"]
        if operation is not None:
            result["operation"] = operation
        if reason is not None:
            result["reason"] = reason
        return result

    def ImportAnalysisEvidence(self, *, evidence_json, dry_run, **kwargs):
        expected_kwargs = {
            "allow_hash_mismatch": False,
            "overwrite_existing": False,
            "apply_labels": True,
            "apply_comments": True,
            "apply_bookmarks": True,
            "apply_functions": False,
            "apply_breakpoints": False,
            "apply_patches": False,
        }
        if kwargs != expected_kwargs:
            raise AssertionError(kwargs)
        self.import_calls.append(dry_run)
        document = json.loads(evidence_json)
        target_rva = int(document["evidence"]["labels"][0]["rva"], 0)
        target_address = hex(self.base + target_rva)
        current = {
            "label": target_rva in self.labels,
            "comment": target_rva in self.comments,
            "bookmark": target_rva in self.bookmarks,
        }
        entries = {
            "label": document["evidence"]["labels"][0],
            "comment": document["evidence"]["comments"][0],
            "bookmark": document["evidence"]["bookmarks"][0],
        }
        actions = [
            self._import_record(kind, entries[kind], target_address, operation="create")
            for kind in ("label", "comment", "bookmark")
            if not current[kind]
        ]
        noops = [
            self._import_record(kind, entries[kind], target_address, reason="already_equal")
            for kind in ("label", "comment", "bookmark")
            if current[kind]
        ]
        validation = {
            "ok": True,
            "valid": True,
            "schema": document["schema"],
            "version": document["version"],
            "counts": document["counts"],
        }
        plan = {
            "module": {"runtimeImageBase": hex(self.base)},
            "evidenceImage": document["image"],
            "identity": {
                "hashMatches": True,
                "hashMismatchAllowed": False,
                "runtimeBase": hex(self.base),
            },
            "selected": {
                "labels": True,
                "comments": True,
                "bookmarks": True,
                "functions": False,
                "breakpoints": False,
                "patches": False,
            },
            "actions": actions,
            "noops": noops,
            "conflicts": [],
            "ignoredCounts": {"functions": 0, "breakpoints": 0, "patches": 0},
            "warnings": [],
            "eventSeq": 17,
            "transactional": False,
            "guard": "session identity + event sequence CAS",
        }
        if dry_run:
            return {
                "ok": True,
                "dryRun": True,
                "canApply": True,
                "wouldMutate": len(actions),
                "validation": validation,
                "plan": plan,
            }

        applied = []
        endpoint = {
            "label": "Label/Set",
            "comment": "Comment/Set",
            "bookmark": "Bookmark/Set",
        }
        for action in actions:
            kind = action["kind"]
            if kind == "label":
                self.labels[target_rva] = {
                    "text": action["text"],
                    "manual": action["manual"],
                }
            elif kind == "comment":
                self.comments[target_rva] = {
                    "text": action["text"],
                    "manual": action["manual"],
                }
            else:
                self.bookmarks[target_rva] = {"manual": action["manual"]}
            applied.append(
                {
                    "action": action,
                    "endpoint": endpoint[kind],
                    "response": {"ok": True},
                    "verified": True,
                }
            )
        return {
            "ok": True,
            "dryRun": False,
            "validation": validation,
            "plan": plan,
            "applied": applied,
            "appliedCount": len(applied),
            "failures": [],
            "verificationFailures": [],
            "partial": False,
        }


class LiveReleaseMatrixTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load_module()

    def test_all_selection_has_exact_x86_x64_parity(self):
        runs = self.mod.select_case_runs("all")
        names_by_arch = {
            arch: [spec.name for selected_arch, spec in runs if selected_arch == arch]
            for arch in ("x64", "x86")
        }
        self.assertEqual(names_by_arch["x64"], names_by_arch["x86"])
        self.assertEqual(len(runs), 2 * len(self.mod.CASE_SPECS))
        self.assertTrue(names_by_arch["x64"])

    def test_specific_case_selectors_preserve_matrix_order_and_deduplicate(self):
        runs = self.mod.select_case_runs(
            "x86", ["dump_main,self_check", "self_check"]
        )
        self.assertEqual(
            [(arch, spec.name) for arch, spec in runs],
            [("x86", "self_check"), ("x86", "dump_main")],
        )

    def test_arch_qualified_case_selects_only_requested_lane(self):
        runs = self.mod.select_case_runs("all", ["x64.self_check"])
        self.assertEqual([(arch, spec.name) for arch, spec in runs], [("x64", "self_check")])

    def test_unknown_or_out_of_scope_case_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "unknown or out-of-scope"):
            self.mod.select_case_runs("x86", ["not_a_case"])
        with self.assertRaisesRegex(ValueError, "unknown or out-of-scope"):
            self.mod.select_case_runs("x86", ["x64.self_check"])

    def test_list_mode_is_read_only(self):
        output = io.StringIO()
        with (
            mock.patch.object(
                self.mod, "snapshot_processes", side_effect=AssertionError("must not inspect processes")
            ),
            redirect_stdout(output),
        ):
            rc = self.mod.main(["--list"])
        payload = json.loads(output.getvalue())
        self.assertEqual(rc, 0)
        self.assertEqual(payload["runCountAll"], 2 * len(self.mod.CASE_SPECS))

    def test_parent_refuses_existing_debugger_and_reports_preflight_error(self):
        existing = self.mod.ProcessIdentity(77, 1, "x64dbg.exe", 9001)

        class Lock:
            def __enter__(self):
                return self

            def __exit__(self, *_):
                return None

        with tempfile.TemporaryDirectory() as temp_dir:
            report_path = Path(temp_dir) / "report.json"
            args = SimpleNamespace(
                arch="x64",
                case=["self_check"],
                run_id="unit-preflight",
                out_dir=temp_dir,
                out=str(report_path),
                bridge=str(ROOT / "src" / "x64dbg.py"),
                timeout_seconds=None,
                take_over_existing_debugger=False,
            )
            with (
                mock.patch.object(self.mod, "_RunLock", Lock),
                mock.patch.object(self.mod, "debugger_processes", return_value=[existing]),
            ):
                rc = self.mod._parent_main(args)
            report = json.loads(report_path.read_text(encoding="utf-8"))
        self.assertEqual(rc, 2)
        self.assertFalse(report["ok"])
        self.assertEqual(report["errors"], 1)
        self.assertEqual(report["testcases"][0]["failure"]["type"], "PREEXISTING_DEBUGGER")

    def test_watchdog_hard_timeout_terminates_exact_worker_pid(self):
        process = _FakeProcess(pid=7331)
        now = [0.0]
        terminations = []

        def sleep(seconds):
            now[0] += seconds

        def terminate(pid):
            terminations.append(pid)
            process.returncode = -1
            return {"ok": True, "pid": pid}

        result = self.mod.wait_with_watchdog(
            process,
            0.25,
            poll_interval=0.1,
            terminate=terminate,
            monotonic=lambda: now[0],
            sleeper=sleep,
        )
        self.assertTrue(result.timed_out)
        self.assertEqual(terminations, [7331])
        self.assertEqual(result.returncode, -1)
        self.assertEqual(result.termination, {"ok": True, "pid": 7331})

    def test_watchdog_normal_exit_does_not_terminate(self):
        process = _FakeProcess(pid=7332)
        polls = [None, 0]
        process.poll = lambda: polls.pop(0)
        now = [0.0]
        terminated = []
        result = self.mod.wait_with_watchdog(
            process,
            5.0,
            terminate=lambda pid: terminated.append(pid),
            monotonic=lambda: now[0],
            sleeper=lambda seconds: now.__setitem__(0, now[0] + seconds),
        )
        self.assertFalse(result.timed_out)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(terminated, [])

    def test_pid_safe_termination_refuses_reused_pid(self):
        expected = self.mod.ProcessIdentity(100, 1, "x64dbg.exe", 111)
        current = self.mod.ProcessIdentity(100, 1, "x64dbg.exe", 222)
        taskkill = mock.Mock()
        result = self.mod.terminate_process_identity(
            expected,
            allowed_names=self.mod.DEBUGGER_NAMES,
            lookup=lambda _: current,
            taskkill=taskkill,
        )
        self.assertFalse(result["ok"])
        self.assertEqual(result["errorCode"], "PID_IDENTITY_MISMATCH")
        taskkill.assert_not_called()

    def test_pid_safe_termination_refuses_unexpected_image(self):
        identity = self.mod.ProcessIdentity(100, 1, "python.exe", 111)
        taskkill = mock.Mock()
        result = self.mod.terminate_process_identity(
            identity,
            allowed_names=self.mod.DEBUGGER_NAMES,
            lookup=lambda _: identity,
            taskkill=taskkill,
        )
        self.assertFalse(result["ok"])
        self.assertEqual(result["errorCode"], "UNEXPECTED_PROCESS_NAME")
        taskkill.assert_not_called()

    def test_cleanup_kills_captured_debugger_tree_and_verifies_exit(self):
        root = self.mod.ProcessIdentity(200, 10, "x32dbg.exe", 1000)
        child = self.mod.ProcessIdentity(201, 200, "fixture.exe", 1001)
        live = {200: root, 201: child}
        killed = []

        def lookup(pid):
            return live.get(pid)

        def taskkill(pid, _timeout):
            killed.append(pid)
            if pid == root.pid:
                live.pop(root.pid, None)
                live.pop(child.pid, None)
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        result = self.mod.cleanup_owned_processes(
            [root], [child], lookup=lookup, taskkill=taskkill
        )
        self.assertTrue(result["ok"], result)
        self.assertEqual(killed, [200])
        self.assertEqual(result["remaining"], [])

    def test_cleanup_failure_is_not_downgraded_to_warning(self):
        root = self.mod.ProcessIdentity(300, 10, "x64dbg.exe", 1000)

        def taskkill(_pid, _timeout):
            raise PermissionError("denied")

        result = self.mod.cleanup_owned_processes(
            [root], [], lookup=lambda _: root, taskkill=taskkill
        )
        self.assertFalse(result["ok"])
        self.assertTrue(result["remaining"])

    def test_worker_start_never_reloads_previous_target(self):
        class Bridge:
            def __init__(self):
                self.kwargs = None

            def RestartDebugger(self, **kwargs):
                self.kwargs = kwargs
                return {"ok": True}

        bridge = Bridge()
        result = self.mod.ensure_debugger_for_worker(bridge, "x64", 12345)
        self.assertTrue(result["ok"])
        self.assertEqual(bridge.kwargs["arch"], "x64")
        self.assertEqual(bridge.kwargs["timeout_ms"], 12345)
        self.assertIs(bridge.kwargs["reload_target"], False)

    def test_scenario_exception_still_requests_debug_stop(self):
        class Bridge:
            stopped = 0

            def DebugStop(self):
                self.stopped += 1
                return "stopped"

        bridge = Bridge()

        def fail(*_):
            raise RuntimeError("expected fixture failure")

        result, cleanup = self.mod.execute_scenario_with_cleanup(
            bridge, fail, r"C:\fixture.exe"
        )
        self.assertFalse(result["ok"])
        self.assertEqual(result["exceptionType"], "RuntimeError")
        self.assertEqual(bridge.stopped, 1)
        self.assertTrue(cleanup["attempted"])
        self.assertEqual(cleanup["debugStop"], "stopped")

    def test_minidump_adapter_checks_verifier_architecture_field(self):
        write_kwargs = {}

        class Bridge:
            @staticmethod
            def InitDebuggee(*_, **__):
                return {"ok": True}

            @staticmethod
            def RunUntil(**_):
                return {"ok": True}

            @staticmethod
            def WriteMiniDump(output_path, **kwargs):
                write_kwargs.update(kwargs)
                Path(output_path).write_bytes(b"MDMP-fixture")
                return {"ok": True}

            @staticmethod
            def VerifyMiniDump(*_, **__):
                return {"ok": True, "valid": True, "architecture": "x86"}

        with tempfile.TemporaryDirectory() as temp_dir:
            result = self.mod._run_minidump_adapter(
                Bridge(), r"C:\fixture.exe", Path(temp_dir), "x86"
            )
        self.assertTrue(result["ok"], result)
        self.assertNotIn("verify", write_kwargs)

    def test_native_coverage_case_is_complete_and_dispatches_special_adapter(self):
        spec = next(item for item in self.mod.CASE_SPECS if item.name == "native_coverage")
        self.assertEqual(spec.scenario, "__native_coverage__")
        self.assertEqual(spec.target, "corpus:deterministic_coverage")
        sentinel = {"ok": True, "adapter": "native"}
        with mock.patch.object(
            self.mod, "_run_native_coverage_adapter", return_value=sentinel
        ) as adapter:
            scenario = self.mod._build_case_scenario(
                spec, SimpleNamespace(SCENARIOS={}), Path(r"C:\artifacts"), "x86"
            )
            result = scenario("bridge", r"C:\deterministic_coverage.exe")
        self.assertIs(result, sentinel)
        adapter.assert_called_once_with(
            "bridge",
            r"C:\deterministic_coverage.exe",
            Path(r"C:\artifacts"),
            "x86",
        )

    def test_native_coverage_adapter_requires_exact_zero_branch_exports(self):
        base = 0x400000
        rvas = {
            "coverage_target": 0x1000,
            "block_entry": 0x1010,
            "block_zero": 0x1020,
            "block_even": 0x1030,
            "block_odd": 0x1040,
            "block_le10": 0x1050,
            "block_gt10": 0x1060,
            "block_final": 0x1070,
            "block_loop": 0x1080,
            "block_switch_0": 0x1090,
            "block_switch_1": 0x10A0,
            "block_switch_2": 0x10B0,
            "block_switch_3": 0x10C0,
            "block_switch_4": 0x10D0,
            "block_switch_5": 0x10E0,
            "block_switch_6": 0x10F0,
            "block_switch_7": 0x1100,
            "block_indirect_even": 0x1110,
            "block_indirect_odd": 0x1120,
            "block_exception_raise": 0x1130,
            "block_exception_handler": 0x1140,
            "coverage_loop": 0x1150,
            "coverage_switch": 0x1160,
            "coverage_indirect": 0x1170,
            "coverage_exception": 0x1180,
            "coverage_self_modify": 0x1190,
            "coverage_smc_entry": 0x11A0,
        }
        expected_path = {
            base + rvas[name]
            for name in (
                "block_entry",
                "block_zero",
                "block_even",
                "block_le10",
                "block_loop",
                "block_switch_0",
                "block_indirect_even",
                "block_exception_raise",
                "block_exception_handler",
                "coverage_loop",
                "coverage_switch",
                "coverage_indirect",
                "coverage_exception",
                "coverage_self_modify",
                "coverage_smc_entry",
                "block_final",
            )
        }

        class Bridge:
            init_kwargs = None
            start_kwargs = None
            run_kwargs = None

            @classmethod
            def InitDebuggee(cls, *_, **kwargs):
                cls.init_kwargs = kwargs
                return {"ok": True}

            @staticmethod
            def RunUntil(**_):
                return {"ok": True}

            @staticmethod
            def GetModuleList():
                return {
                    "modules": [
                        {
                            "name": "deterministic_coverage.exe",
                            "base": hex(base),
                            "size": "0x3000",
                        }
                    ]
                }

            @staticmethod
            def CaptureSymbolicBreakpoint(**_):
                return {"ok": True, "resolvedAddr": hex(base + rvas["coverage_target"])}

            @staticmethod
            def SetExceptionPolicy(*_, **__):
                return {"ok": True}

            @classmethod
            def StartNativeTrace(cls, **kwargs):
                cls.start_kwargs = kwargs
                return {"ok": True, "traceId": "native-coverage-1"}

            @classmethod
            def RunNativeTrace(cls, **kwargs):
                cls.run_kwargs = kwargs
                return {
                    "ok": True,
                    "evidence": {
                        "matchedSteps": len(expected_path),
                        "hits": [
                            {"ip": hex(address), "hits": 1}
                            for address in sorted(expected_path)
                        ],
                    },
                }

            @staticmethod
            def QuerySymbols(*_, **__):
                return {
                    "symbols": [
                        {"name": name, "rva": hex(rva), "type": "export"}
                        for name, rva in rvas.items()
                    ]
                }

            @staticmethod
            def ClearNativeTrace(trace_id):
                return {"ok": trace_id == "native-coverage-1"}

        with tempfile.TemporaryDirectory() as temp_dir:
            result = self.mod._run_native_coverage_adapter(
                Bridge(),
                r"C:\deterministic_coverage.exe",
                Path(temp_dir),
                "x86",
            )
        self.assertTrue(result["ok"], result)
        self.assertEqual(Bridge.init_kwargs["arguments"], ["0"])
        self.assertEqual(Bridge.start_kwargs["mode"], "coverage")
        self.assertEqual(Bridge.start_kwargs["range_start"], "0x400000")
        self.assertEqual(Bridge.start_kwargs["max_steps"], 15000)
        self.assertEqual(Bridge.run_kwargs["max_steps"], 15000)
        self.assertTrue(result["capturedEntry"]["matches"])
        self.assertNotIn(base + rvas["coverage_target"], expected_path)
        self.assertEqual(result["missingExportSymbols"], [])
        self.assertEqual(result["missingExpected"], [])
        self.assertEqual(result["unexpectedCovered"], [])

    def test_exception_fixture_launch_prefers_nested_native_session_identity(self):
        session = {
            "sessionId": "session-live-1",
            "generation": 7,
            "processId": 4242,
            "eventSeq": 19,
        }

        class Bridge:
            @staticmethod
            def InitDebuggee(*_args, **_kwargs):
                return {"ok": True, "state": {"session": dict(session)}}

            @staticmethod
            def RunUntil(*_args, **_kwargs):
                return {
                    "ok": True,
                    "state": {"ok": True, "pid": 0, "paused": True},
                    "waitState": {"state": dict(session)},
                }

        result = self.mod._launch_exception_fixture(
            Bridge(), r"C:\exception_disposition.exe", "handled"
        )
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["sessionId"], session["sessionId"])
        self.assertEqual(result["generation"], session["generation"])
        self.assertEqual(result["processId"], session["processId"])

    def test_exception_policy_cases_have_x86_x64_special_adapter_coverage(self):
        expected = {
            "exception_policy_first_chance": "__exception_policy_first_chance__",
            "exception_policy_precedence": "__exception_policy_precedence__",
            "exception_policy_second_chance": "__exception_policy_second_chance__",
            "exception_policy_lifecycle": "__exception_policy_lifecycle__",
        }
        specs = {item.name: item for item in self.mod.CASE_SPECS}
        for name, scenario_name in expected.items():
            with self.subTest(case=name):
                self.assertIn(name, specs)
                self.assertEqual(specs[name].scenario, scenario_name)
                self.assertEqual(specs[name].target, "corpus:exception_disposition")
                self.assertGreaterEqual(specs[name].timeout_seconds, 180)
        selected = self.mod.select_case_runs("all", expected)
        self.assertEqual(
            {(arch, spec.name) for arch, spec in selected},
            {(arch, name) for arch in ("x86", "x64") for name in expected},
        )

    def test_exception_history_record_contract_requires_causal_applied_fields(self):
        bridge = _ExceptionPolicyBridge()
        bridge.InitDebuggee(r"C:\fixture.exe", arguments=["handled"])
        record = bridge._record(
            bridge.EXACT,
            first=True,
            action="not_handled",
            rule_id="exact",
            selector="0xe0424242",
            auto=True,
            command="con 1",
            submitted=True,
            status="submitted",
            disposition="not_handled",
        )
        complete = self.mod._history_record_contract(record)
        self.assertTrue(complete["ok"], complete)
        for field in (
            "bridgeInstanceId",
            "eventSeq",
            "timestamp100ns",
            "lastUpdateTimestamp100ns",
            "ruleId",
            "matchedSelector",
            "continuationSource",
            "continuationClaimed",
            "commandSubmitted",
            "dispositionSubmitted",
            "resumeRequested",
            "resumeSubmitted",
            "disposition",
            "requestedDisposition",
            "appliedDisposition",
            "outcome",
        ):
            with self.subTest(field=field):
                incomplete = dict(record)
                del incomplete[field]
                result = self.mod._history_record_contract(incomplete)
                self.assertFalse(result["ok"], result)
                self.assertIn(field, result["missing"])

    def test_exception_policy_first_chance_adapter_proves_both_exit_oracles(self):
        result = self.mod._run_exception_policy_first_chance_adapter(
            _ExceptionPolicyBridge(),
            r"C:\exception_disposition.exe",
            Path(r"C:\artifacts"),
            "x64",
        )
        self.assertTrue(result["ok"], result)
        passed = result["notHandledToSeh"]
        swallowed = result["handledByDebugger"]
        veh = result["notHandledToVehContinue"]
        self.assertEqual(passed["observedExitCode"], 0)
        self.assertEqual(swallowed["observedExitCode"], 68)
        self.assertEqual(veh["fixtureMode"], "first-chance")
        self.assertEqual(veh["observedExitCode"], 0)
        self.assertEqual(
            passed["historyContract"]["records"][0]["command"], "con 1"
        )
        self.assertEqual(
            swallowed["historyContract"]["records"][0]["command"], "con"
        )

    def test_exception_policy_precedence_adapter_proves_rules_and_cursor(self):
        result = self.mod._run_exception_policy_precedence_adapter(
            _ExceptionPolicyBridge(),
            r"C:\exception_disposition.exe",
            Path(r"C:\artifacts"),
            "x86",
        )
        self.assertTrue(result["ok"], result)
        records = result["historyContract"]["records"]
        self.assertEqual(
            [record["ruleId"] for record in records],
            ["exact-code", "masked-family", "wildcard-fallback"],
        )
        self.assertEqual(
            [record["matchedSelector"] for record in records],
            ["0xe0424242", "0xe0420000/0xffff0000", "*"],
        )
        self.assertEqual(
            [page["afterSeq"] for page in result["cursorContract"]["pages"]],
            [0, 1, 2],
        )

    def test_exception_policy_second_chance_adapter_proves_first_then_second(self):
        result = self.mod._run_exception_policy_second_chance_adapter(
            _ExceptionPolicyBridge(),
            r"C:\exception_disposition.exe",
            Path(r"C:\artifacts"),
            "x64",
        )
        self.assertTrue(result["ok"], result)
        first, second = result["historyContract"]["records"]
        self.assertTrue(first["firstChance"])
        self.assertEqual(first["disposition"], "not_handled")
        self.assertFalse(second["firstChance"])
        self.assertEqual(second["action"], "pause")
        self.assertTrue(result["pause"]["paused"])

    def test_exception_policy_lifecycle_adapter_proves_exactly_once_and_reset(self):
        result = self.mod._run_exception_policy_lifecycle_adapter(
            _ExceptionPolicyBridge(),
            r"C:\exception_disposition.exe",
            Path(r"C:\artifacts"),
            "x86",
        )
        self.assertTrue(result["ok"], result)
        self.assertTrue(result["exactlyOnceOk"])
        self.assertTrue(result["staleRejectedOk"])
        self.assertEqual(
            result["duplicateManualDisposition"]["errorCode"],
            "EXCEPTION_ALREADY_CLAIMED",
        )
        self.assertTrue(result["manualHistoryOk"])
        self.assertTrue(result["historyClearOk"])
        self.assertTrue(result["relaunchIsolated"])
        self.assertFalse(result["freshPolicy"]["policy"]["enabled"])
        self.assertTrue(result["seededNonemptyOk"])
        self.assertTrue(result["explicitClearOk"])
        self.assertEqual(result["freshHistory"]["history"], [])
        self.assertEqual(result["historyAfterClear"]["history"], [])
        self.assertGreaterEqual(result["clearPolicy"]["historyCleared"], 1)
        self.assertEqual(result["postClearPolicy"]["policy"]["rules"], [])

    def test_evidence_roundtrip_clears_persisted_database_and_proves_exact_lifecycle(self):
        fixture_root = ROOT / "tools" / "bin" / "e2e"
        fixture_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=fixture_root) as raw_dir:
            run_dir = Path(raw_dir)
            fixture = run_dir / "fixture.exe"
            fixture.write_bytes(b"strict-evidence-fixture")
            artifact_dir = run_dir / "artifacts"
            bridge = _EvidenceBridge()
            result = self.mod._run_evidence_roundtrip_adapter(
                bridge, str(fixture), artifact_dir, "x64"
            )

        self.assertTrue(result["ok"], result)
        self.assertEqual(bridge.init_count, 2)
        self.assertEqual(bridge.import_calls, [True, False, False])
        self.assertEqual(bridge.labels, {})
        self.assertEqual(bridge.comments, {})
        self.assertEqual(bridge.bookmarks, {})
        self.assertEqual(bridge.functions, {})
        self.assertTrue(result["sourceBaselineClear"]["ok"])
        self.assertTrue(result["sourcePostExportClear"]["ok"])
        self.assertTrue(result["secondBaselineClear"]["ok"])
        self.assertTrue(result["exportContract"]["ok"])
        self.assertTrue(result["dryRunContract"]["ok"])
        self.assertTrue(result["applyContract"]["ok"])
        self.assertTrue(result["repeatContract"]["ok"])
        self.assertTrue(result["finalClear"]["ok"])
        self.assertEqual(result["dryRun"]["wouldMutate"], 3)
        self.assertEqual(result["apply"]["appliedCount"], 3)
        self.assertEqual(result["repeat"]["appliedCount"], 0)
        self.assertTrue(any(kind == "function" for _phase, kind, _rva, _ in bridge.delete_calls))

    def test_annotation_cleanup_guard_rejects_non_fixture_module(self):
        with tempfile.TemporaryDirectory() as raw_dir:
            artifact_dir = Path(raw_dir) / "artifacts"
            module = {
                "name": "user.exe",
                "path": str(Path(raw_dir) / "user.exe"),
                "base": "0x140000000",
            }
            guard = self.mod._generated_fixture_guard(
                module, module["path"], artifact_dir
            )
        self.assertFalse(guard["ok"])
        self.assertEqual(guard["errorCode"], "ANNOTATION_CLEANUP_PATH_REJECTED")

    def test_reported_skip_is_forced_to_failure(self):
        class Bridge:
            @staticmethod
            def DebugStop():
                return "stopped"

        result, _ = self.mod.execute_scenario_with_cleanup(
            Bridge(), lambda *_: {"ok": True, "skipped": True}, r"C:\fixture.exe"
        )
        self.assertFalse(result["ok"])
        self.assertTrue(result["skipRejected"])

    def test_junit_like_aggregate_counts_skip_as_failure(self):
        report = {
            "testcases": [
                {"status": "success", "time": 0.5},
                {"status": "failure", "time": 1.0, "reportedSkipped": True},
                {"status": "error", "time": 1.5},
            ]
        }
        result = self.mod._finalize_report(report)
        self.assertEqual(result["tests"], 3)
        self.assertEqual(result["failures"], 1)
        self.assertEqual(result["errors"], 1)
        self.assertEqual(result["skipped"], 1)
        self.assertEqual(result["time"], 3.0)
        self.assertFalse(result["ok"])

    def test_atomic_report_replacement_never_leaves_partial_json(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "report.json"
            self.mod._atomic_write_json(path, {"generation": 1})
            self.mod._atomic_write_json(path, {"generation": 2, "ok": True})
            payload = json.loads(path.read_text(encoding="utf-8"))
            leftovers = list(path.parent.glob(".report.json.*.tmp"))
        self.assertEqual(payload, {"generation": 2, "ok": True})
        self.assertEqual(leftovers, [])


if __name__ == "__main__":
    unittest.main()
