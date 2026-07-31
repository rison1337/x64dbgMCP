import importlib.util
import json
import os
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock


MODULE_PATH = Path(__file__).resolve().parents[1] / "src" / "x64dbg.py"
TOKEN_A = "a1" * 32
TOKEN_B = "b2" * 32


def _load_bridge():
    spec = importlib.util.spec_from_file_location("x64dbg_bridge_auth", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class FakeResponse:
    def __init__(self, status=200, body='{"ok":true}', content_type="application/json"):
        self.status_code = int(status)
        # requests treats redirects as truthy; the transport must still reject
        # them because an authenticated bridge response is always final.
        self.ok = 200 <= self.status_code < 400
        self.content = body.encode("utf-8")
        self.text = body
        self.headers = {"Content-Type": content_type}


class FakeSession:
    def __init__(self, *actions):
        self.actions = list(actions)
        self.calls = []

    def _next(self, method, url, kwargs):
        self.calls.append((method, url, kwargs))
        action = self.actions.pop(0)
        if isinstance(action, BaseException):
            raise action
        return action

    def get(self, url, **kwargs):
        return self._next("GET", url, kwargs)

    def post(self, url, **kwargs):
        return self._next("POST", url, kwargs)


def _write_descriptor(
    directory: Path,
    *,
    pid: int,
    token: str,
    port: int = 8888,
    start_time: int = 133700000,
    bridge_id: str = "bridge-a",
    arch: str = "x64",
    extra_lines=(),
) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"bridge-{pid}.token"
    lines = [
        "version=1",
        f"pid={pid}",
        f"processStartTime100ns={start_time}",
        f"bridgeInstanceId={bridge_id}",
        f"port={port}",
        f"arch={arch}",
        f"token={token}",
        *list(extra_lines),
    ]
    path.write_text("\n".join(lines) + "\n", encoding="ascii")
    return path


class BridgeAuthContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load_bridge()

    def setUp(self):
        self.original_url = self.mod.x64dbg_server_url
        self.original_http_local = self.mod._HTTP_LOCAL
        self.mod.x64dbg_server_url = self.mod.DEFAULT_X64DBG_SERVER
        self.mod._HTTP_LOCAL = threading.local()
        self.mod._invalidate_bridge_auth_cache()
        with self.mod._RUNTIME_LOCK:
            self.mod._RUNTIME_STATE["bridgeIdentity"] = None
            self.mod._RUNTIME_STATE["boundSession"] = None

    def tearDown(self):
        session = getattr(self.mod._HTTP_LOCAL, "session", None)
        if session is not None:
            session.close()
        self.mod._HTTP_LOCAL = self.original_http_local
        self.mod.x64dbg_server_url = self.original_url
        self.mod._invalidate_bridge_auth_cache()

    def test_descriptor_parser_accepts_complete_descriptor(self):
        with tempfile.TemporaryDirectory() as raw_dir:
            path = _write_descriptor(Path(raw_dir), pid=4242, token=TOKEN_A)
            parsed = self.mod._parse_bridge_auth_file(path)

        self.assertEqual(parsed["token"], TOKEN_A)
        self.assertEqual(parsed["pid"], 4242)
        self.assertEqual(parsed["processStartTime100ns"], 133700000)
        self.assertEqual(parsed["bridgeInstanceId"], "bridge-a")
        self.assertEqual(parsed["port"], 8888)
        self.assertEqual(parsed["arch"], "x64")
        self.assertNotIn(TOKEN_A, json.dumps({k: v for k, v in parsed.items() if k != "token"}))

    def test_descriptor_parser_normalizes_uppercase_token(self):
        with tempfile.TemporaryDirectory() as raw_dir:
            path = _write_descriptor(Path(raw_dir), pid=7, token=TOKEN_A.upper())
            parsed = self.mod._parse_bridge_auth_file(path)
        self.assertEqual(parsed["token"], TOKEN_A)

    def test_descriptor_parser_rejects_missing_security_identity_fields(self):
        required_lines = {
            "pid": "pid=44",
            "processStartTime100ns": "processStartTime100ns=99",
            "bridgeInstanceId": "bridgeInstanceId=bridge-z",
            "port": "port=8888",
            "arch": "arch=x86",
            "token": f"token={TOKEN_A}",
        }
        with tempfile.TemporaryDirectory() as raw_dir:
            directory = Path(raw_dir)
            for missing in required_lines:
                with self.subTest(missing=missing):
                    path = directory / f"missing-{missing}.token"
                    lines = ["version=1"] + [
                        line for name, line in required_lines.items() if name != missing
                    ]
                    path.write_text("\n".join(lines) + "\n", encoding="ascii")
                    self.assertEqual(self.mod._parse_bridge_auth_file(path), {})

    def test_descriptor_parser_rejects_malformed_duplicate_and_oversized_files(self):
        invalid_payloads = [
            "version=2\npid=1\ntoken=" + TOKEN_A + "\n",
            "version=1\npid=1\ntoken=not-hex\n",
            "version=1\npid=0\ntoken=" + TOKEN_A + "\n",
            (
                "version=1\npid=1\nprocessStartTime100ns=2\n"
                "bridgeInstanceId=b\nport=8888\narch=x64\n"
                f"token={TOKEN_A}\ntoken={TOKEN_B}\n"
            ),
        ]
        with tempfile.TemporaryDirectory() as raw_dir:
            directory = Path(raw_dir)
            for index, payload in enumerate(invalid_payloads):
                with self.subTest(index=index):
                    path = directory / f"invalid-{index}.token"
                    path.write_text(payload, encoding="ascii")
                    self.assertEqual(self.mod._parse_bridge_auth_file(path), {})
            oversized = directory / "oversized.token"
            oversized.write_bytes(b"x" * 4097)
            self.assertEqual(self.mod._parse_bridge_auth_file(oversized), {})
            non_ascii = directory / "non-ascii.token"
            non_ascii.write_bytes(b"version=1\npid=1\ntoken=" + TOKEN_A.encode() + b"\xff")
            self.assertEqual(self.mod._parse_bridge_auth_file(non_ascii), {})

    def test_url_resolver_accepts_only_plain_loopback_root_urls(self):
        valid = (
            "http://127.0.0.1:8888/",
            "http://localhost:9999/",
        )
        for url in valid:
            with self.subTest(valid=url), mock.patch.dict(
                os.environ, {"X64DBG_URL": url}, clear=False
            ), mock.patch.object(sys, "argv", ["x64dbg.py"]):
                self.assertEqual(self.mod._resolve_server_url_from_args_env(), url)

        invalid = (
            "https://127.0.0.1:8888/",
            "http://[::1]:8888/",
            "http://192.168.1.2:8888/",
            "http://example.test:8888/",
            "http://127.0.0.1.evil.test:8888/",
            "http://user:password@127.0.0.1:8888/",
            "http://127.0.0.1:8888/bridge-prefix",
            "http://127.0.0.1:8888/?token=leak",
            "http://127.0.0.1:8888/#fragment",
            "http://127.0.0.1:not-a-port/",
        )
        for url in invalid:
            with self.subTest(invalid=url), mock.patch.dict(
                os.environ, {"X64DBG_URL": url}, clear=False
            ), mock.patch.object(sys, "argv", ["x64dbg.py"]):
                self.assertEqual(
                    self.mod._resolve_server_url_from_args_env(),
                    self.mod.DEFAULT_X64DBG_SERVER,
                )

    def test_url_resolver_rejects_invalid_argv_url_too(self):
        with mock.patch.dict(os.environ, {}, clear=True), mock.patch.object(
            sys, "argv", ["x64dbg.py", "http://attacker.test:8888/"]
        ):
            self.assertEqual(
                self.mod._resolve_server_url_from_args_env(),
                self.mod.DEFAULT_X64DBG_SERVER,
            )

    def test_url_setter_refuses_remote_and_normalizes_valid_loopback(self):
        original = self.mod.x64dbg_server_url
        self.mod.set_x64dbg_server_url("http://attacker.test:8888/")
        self.assertEqual(self.mod.x64dbg_server_url, original)

        self.mod.set_x64dbg_server_url("http://localhost:7777")
        self.assertEqual(self.mod.x64dbg_server_url, "http://localhost:7777/")

    def test_requests_session_ignores_proxy_environment(self):
        session = self.mod._get_http_session()
        self.assertFalse(
            session.trust_env,
            "bridge auth must never use HTTP_PROXY/NETRC environment state",
        )

    def test_debugger_stop_invalidates_rotated_bridge_auth_and_identity(self):
        with self.mod._BRIDGE_AUTH_LOCK:
            self.mod._BRIDGE_AUTH_CACHE.update(
                {
                    "source": "descriptor",
                    "token": TOKEN_A,
                    "pid": 101,
                    "port": 8888,
                }
            )
        with self.mod._RUNTIME_LOCK:
            self.mod._RUNTIME_STATE.update(
                {
                    "bridgeIdentity": {
                        "bridgeInstanceId": "dead-bridge",
                        "debuggerPid": 101,
                    },
                    "selectedBridgeInstanceId": "dead-bridge",
                    "selectedBridgeDebuggerPid": 101,
                    "selectedBridgeAt": "now",
                }
            )
        completed = mock.Mock(
            returncode=0,
            stdout="",
            stderr="",
        )
        with mock.patch.object(
            self.mod, "_list_debugger_processes", side_effect=[[], [], []]
        ), mock.patch.object(
            self.mod.subprocess, "run", return_value=completed
        ):
            result = self.mod._stop_debugger_processes("auto", timeout_ms=1)

        self.assertTrue(result["ok"])
        with self.mod._BRIDGE_AUTH_LOCK:
            self.assertEqual(self.mod._BRIDGE_AUTH_CACHE, {})
        with self.mod._RUNTIME_LOCK:
            self.assertEqual(self.mod._RUNTIME_STATE["bridgeIdentity"], {})
            self.assertIsNone(
                self.mod._RUNTIME_STATE["selectedBridgeInstanceId"]
            )
            self.assertEqual(
                self.mod._RUNTIME_STATE["selectedBridgeDebuggerPid"], 0
            )

    def test_transport_disables_redirects_for_get_and_post(self):
        session = FakeSession(FakeResponse(), FakeResponse())
        with mock.patch.object(self.mod, "_get_http_session", return_value=session), mock.patch.object(
            self.mod, "_discover_bridge_auth_token", return_value=TOKEN_A
        ):
            first = self.mod._bridge_request("GET", "Status", guard="none", log=False)
            second = self.mod._bridge_request(
                "POST", "Eval/Batch", form_data={"expressions": "[]"}, guard="none", log=False
            )
        self.assertTrue(first.ok)
        self.assertTrue(second.ok)
        self.assertIs(session.calls[0][2].get("allow_redirects"), False)
        self.assertIs(session.calls[1][2].get("allow_redirects"), False)

    def test_transport_rejects_non_2xx_even_when_requests_marks_it_ok(self):
        session = FakeSession(FakeResponse(status=302, body="redirect", content_type="text/plain"))
        with mock.patch.object(self.mod, "_get_http_session", return_value=session), mock.patch.object(
            self.mod, "_discover_bridge_auth_token", return_value=TOKEN_A
        ):
            result = self.mod._bridge_request("GET", "Bridge/Hello", guard="none", log=False)
        self.assertFalse(result.ok)
        self.assertIsNotNone(result.error)
        self.assertEqual(result.error.http_status, 302)

    def test_discovery_matches_configured_port_not_newest_other_debugger(self):
        with tempfile.TemporaryDirectory() as raw_dir, mock.patch.dict(
            os.environ, {"LOCALAPPDATA": raw_dir}, clear=False
        ):
            os.environ.pop("X64DBG_MCP_TOKEN", None)
            directory = Path(raw_dir) / "x64dbgMCP"
            wanted = _write_descriptor(
                directory, pid=101, token=TOKEN_A, port=8888, bridge_id="bridge-8888"
            )
            other = _write_descriptor(
                directory, pid=202, token=TOKEN_B, port=9999, bridge_id="bridge-9999", arch="x86"
            )
            os.utime(wanted, ns=(1_000_000_000, 1_000_000_000))
            os.utime(other, ns=(2_000_000_000, 2_000_000_000))
            self.mod.x64dbg_server_url = "http://127.0.0.1:8888/"
            self.mod._invalidate_bridge_auth_cache()
            with mock.patch.object(
                self.mod,
                "_list_processes",
                return_value=[
                    {"pid": 101, "exe": "x64dbg.exe"},
                    {"pid": 202, "exe": "x32dbg.exe"},
                ],
            ):
                selected = self.mod._discover_bridge_auth_token()
        self.assertEqual(selected, TOKEN_A)

    def test_discovery_ignores_static_environment_token_override(self):
        with tempfile.TemporaryDirectory() as raw_dir, mock.patch.dict(
            os.environ,
            {"LOCALAPPDATA": raw_dir, "X64DBG_MCP_TOKEN": TOKEN_B},
            clear=False,
        ):
            _write_descriptor(
                Path(raw_dir) / "x64dbgMCP", pid=101, token=TOKEN_A, port=8888
            )
            self.mod.x64dbg_server_url = "http://127.0.0.1:8888/"
            self.mod._invalidate_bridge_auth_cache()
            with mock.patch.object(
                self.mod,
                "_list_processes",
                return_value=[{"pid": 101, "exe": "x64dbg.exe"}],
            ):
                selected = self.mod._discover_bridge_auth_token()
        self.assertEqual(selected, TOKEN_A)

    def test_hello_binding_fails_closed_without_descriptor_identity(self):
        self.mod._invalidate_bridge_auth_cache()
        error = self.mod._validate_hello_auth_binding({"ok": True})
        self.assertIsNotNone(error)
        self.assertEqual(error.code, "AUTH_BINDING_MISSING")

    def test_discovery_uses_fast_cache_after_first_match(self):
        with tempfile.TemporaryDirectory() as raw_dir, mock.patch.dict(
            os.environ, {"LOCALAPPDATA": raw_dir}, clear=False
        ):
            os.environ.pop("X64DBG_MCP_TOKEN", None)
            _write_descriptor(
                Path(raw_dir) / "x64dbgMCP", pid=303, token=TOKEN_A, port=8888
            )
            self.mod.x64dbg_server_url = "http://127.0.0.1:8888/"
            self.mod._invalidate_bridge_auth_cache()
            with mock.patch.object(
                self.mod,
                "_list_processes",
                return_value=[{"pid": 303, "exe": "x64dbg.exe"}],
            ):
                self.assertEqual(self.mod._discover_bridge_auth_token(), TOKEN_A)

    def test_discovery_removes_only_strictly_named_dead_pid_descriptors(self):
        with tempfile.TemporaryDirectory() as raw_dir, mock.patch.dict(
            os.environ, {"LOCALAPPDATA": raw_dir}, clear=False
        ):
            os.environ.pop("X64DBG_MCP_TOKEN", None)
            directory = Path(raw_dir) / "x64dbgMCP"
            live = _write_descriptor(directory, pid=101, token=TOKEN_A, port=8888)
            stale = _write_descriptor(directory, pid=202, token=TOKEN_B, port=8888)
            unrelated = directory / "bridge-not-a-pid.token"
            unrelated.write_text("preserve", encoding="ascii")
            with mock.patch.object(
                self.mod,
                "_list_processes",
                return_value=[{"pid": 101, "exe": "x64dbg.exe"}],
            ):
                selected = self.mod._discover_bridge_auth_token()
            self.assertEqual(selected, TOKEN_A)
            self.assertTrue(live.exists())
            self.assertFalse(stale.exists())
            self.assertTrue(unrelated.exists())
            with mock.patch.object(
                self.mod,
                "_list_processes",
                side_effect=AssertionError("full process discovery repeated on cache hit"),
            ):
                self.assertEqual(self.mod._discover_bridge_auth_token(), TOKEN_A)

    def test_401_invalidates_token_cache_without_retrying_mutation(self):
        session = FakeSession(
            FakeResponse(
                status=401,
                body=(
                    '{"ok":false,"error":{"code":"authentication_required",'
                    '"message":"invalid token","retryable":false}}'
                ),
            )
        )
        with self.mod._BRIDGE_AUTH_LOCK:
            self.mod._BRIDGE_AUTH_CACHE.update({"key": "old", "token": TOKEN_A})
        with mock.patch.object(self.mod, "_get_http_session", return_value=session), mock.patch.object(
            self.mod, "_discover_bridge_auth_token", return_value=TOKEN_A
        ):
            result = self.mod._bridge_request(
                "POST", "Trace/Stop", form_data={"traceId": "trace-a"}, guard="none", log=False
            )
        self.assertFalse(result.ok)
        self.assertEqual(result.error.code, "AUTHENTICATION_REQUIRED")
        self.assertEqual(len(session.calls), 1)
        self.assertEqual(session.calls[0][2]["headers"][self.mod.BRIDGE_AUTH_HEADER], TOKEN_A)
        with self.mod._BRIDGE_AUTH_LOCK:
            self.assertEqual(self.mod._BRIDGE_AUTH_CACHE, {})

    def test_401_rediscovers_token_once_for_idempotent_unguarded_get(self):
        session = FakeSession(
            FakeResponse(
                status=401,
                body=(
                    '{"ok":false,"error":{"code":"authentication_required",'
                    '"message":"rotated token","retryable":false}}'
                ),
            ),
            FakeResponse(body='{"ok":true,"value":7}'),
        )
        with mock.patch.object(
            self.mod, "_get_http_session", return_value=session
        ), mock.patch.object(
            self.mod,
            "_discover_bridge_auth_token",
            side_effect=[TOKEN_A, TOKEN_B],
        ):
            result = self.mod._bridge_request(
                "GET",
                "Eval/Batch",
                params={"expressions": "[]"},
                guard="none",
                idempotent=True,
                log=False,
            )
        self.assertTrue(result.ok, result)
        self.assertEqual(result.data["value"], 7)
        self.assertEqual(len(session.calls), 2)
        first_headers = session.calls[0][2]["headers"]
        second_headers = session.calls[1][2]["headers"]
        self.assertEqual(first_headers[self.mod.BRIDGE_AUTH_HEADER], TOKEN_A)
        self.assertEqual(second_headers[self.mod.BRIDGE_AUTH_HEADER], TOKEN_B)
        self.assertEqual(
            first_headers["X-MCP-Request-Id"],
            second_headers["X-MCP-Request-Id"],
        )

    def test_auth_token_is_header_only_and_redacted_from_logs(self):
        session = FakeSession(FakeResponse(body='{"ok":true,"value":7}'))
        events = []
        with mock.patch.object(self.mod, "_get_http_session", return_value=session), mock.patch.object(
            self.mod, "_discover_bridge_auth_token", return_value=TOKEN_A
        ), mock.patch.object(self.mod, "_log_event", side_effect=lambda *a, **k: events.append((a, k))):
            result = self.mod._bridge_request(
                "POST",
                "Eval/Batch",
                params={"visible": "yes"},
                form_data={"expressions": "[]"},
                guard="none",
                log=True,
            )
        self.assertTrue(result.ok)
        method, url, kwargs = session.calls[0]
        self.assertEqual(method, "POST")
        self.assertNotIn(TOKEN_A, url)
        self.assertNotIn(TOKEN_A, json.dumps(kwargs.get("params"), default=str))
        self.assertNotIn(TOKEN_A, json.dumps(kwargs.get("data"), default=str))
        self.assertEqual(kwargs["headers"][self.mod.BRIDGE_AUTH_HEADER], TOKEN_A)
        self.assertNotIn(TOKEN_A, json.dumps(events, default=str))
        redacted = self.mod._redact_sensitive(
            {"headers": {self.mod.BRIDGE_AUTH_HEADER: TOKEN_A, "Accept": "application/json"}}
        )
        self.assertEqual(redacted["headers"][self.mod.BRIDGE_AUTH_HEADER], "<redacted>")


if __name__ == "__main__":
    unittest.main()
