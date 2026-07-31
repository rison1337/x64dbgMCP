import hashlib
import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest import mock


MODULE_PATH = Path(__file__).resolve().parents[1] / "src" / "x64dbg.py"


def _load_bridge():
    spec = importlib.util.spec_from_file_location("x64dbg_target_identity", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class _Response:
    status_code = 200
    text = '{"ok":true}'
    content = text.encode("utf-8")
    headers = {"Content-Type": "application/json"}


class _Session:
    def __init__(self):
        self.calls = []

    def post(self, url, **kwargs):
        self.calls.append(("POST", url, kwargs))
        return _Response()

    def get(self, url, **kwargs):
        self.calls.append(("GET", url, kwargs))
        return _Response()


class TargetIdentityCasTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load_bridge()

    def setUp(self):
        self.digest = "AB" * 32
        identity = {
            "bridgeInstanceId": "bridge-v4",
            "sessionId": "session-v4",
            "sessionGeneration": 3,
            "debuggeePid": 4242,
            "eventSeq": 19,
            "protocolVersion": 4,
            "imageSha256": self.digest,
            "capabilities": {
                "strictSessionGuards": {
                    "version": 2,
                    "targetSha256": True,
                    "eventCas": True,
                }
            },
            "routePolicyCompatible": True,
            "routePolicySourceId": self.mod._ROUTE_POLICY_ID,
        }
        with self.mod._RUNTIME_LOCK:
            self.mod._RUNTIME_STATE["bridgeIdentity"] = dict(identity)
            self.mod._RUNTIME_STATE["boundSession"] = {
                **identity,
                "pid": 4242,
                "imagePath": r"C:\\target.exe",
                "strict": True,
            }

    def test_v4_headers_always_include_hash_and_event_cas(self):
        headers, error = self.mod._guard_headers(
            "session", request_id="request-1"
        )
        self.assertIsNone(error)
        self.assertEqual(headers["X-MCP-Debuggee-SHA256"], self.digest)
        self.assertEqual(headers["X-MCP-Event-Seq"], "19")

    def test_fresh_session_event_overrides_creation_time_binding_event(self):
        with self.mod._RUNTIME_LOCK:
            self.mod._RUNTIME_STATE["bridgeIdentity"]["eventSeq"] = 27
            self.mod._RUNTIME_STATE["boundSession"]["eventSeq"] = 19
        identity = self.mod._identity_for_guard()
        self.assertEqual(identity["eventSeq"], 27)
        headers, error = self.mod._guard_headers("session", request_id="request-fresh")
        self.assertIsNone(error)
        self.assertEqual(headers["X-MCP-Event-Seq"], "27")

    def test_missing_hash_fails_closed_before_network(self):
        with self.mod._RUNTIME_LOCK:
            self.mod._RUNTIME_STATE["bridgeIdentity"]["imageSha256"] = ""
            self.mod._RUNTIME_STATE["boundSession"]["imageSha256"] = ""
        session = _Session()
        with mock.patch.object(self.mod, "_get_http_session", return_value=session):
            result = self.mod._bridge_request(
                "POST", "Memory/Write", form_data={"addr": "0x1", "data": "00"}, log=False
            )
        self.assertFalse(result.ok)
        self.assertEqual(result.error.code, "TARGET_IDENTITY_UNAVAILABLE")
        self.assertEqual(len(session.calls), 1)
        self.assertTrue(session.calls[0][1].endswith("/Debug/SessionState"))

    def test_same_path_replacement_is_detected_locally(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "target.exe"
            path.write_bytes(b"first image")
            first = hashlib.sha256(path.read_bytes()).hexdigest().upper()
            with self.mod._RUNTIME_LOCK:
                self.mod._RUNTIME_STATE["bridgeIdentity"]["imageSha256"] = first
                self.mod._RUNTIME_STATE["boundSession"]["imageSha256"] = first
                self.mod._RUNTIME_STATE["boundSession"]["imagePath"] = str(path)
            path.write_bytes(b"replacement image")
            headers, error = self.mod._guard_headers(
                "session", request_id="request-2"
            )
        self.assertIsNotNone(error)
        self.assertEqual(error.code, "STALE_TARGET_IDENTITY")
        self.assertEqual(headers.get("X-MCP-Debuggee-SHA256"), first)

    def test_snapshot_owner_contains_hash_and_rejects_hash_turnover(self):
        owner = self.mod._capture_snapshot_owner(require_thread=False)
        self.assertEqual(owner["imageSha256"], self.digest)
        self.assertTrue(owner["strong"])
        with mock.patch.object(
            self.mod,
            "_capture_snapshot_owner",
            return_value={**owner, "imageSha256": "CD" * 32},
        ):
            result = self.mod._snapshot_owner_match(owner)
        self.assertFalse(result["matches"])
        self.assertIn("imageSha256", result["mismatches"])


if __name__ == "__main__":
    unittest.main()
