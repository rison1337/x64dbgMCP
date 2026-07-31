import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CPP = (ROOT / "src" / "MCPx64dbg.cpp").read_text(encoding="utf-8")
CMAKE = (ROOT / "CMakeLists.txt").read_text(encoding="utf-8")


def _function_body(name: str) -> str:
    match = re.search(
        rf"\b(?:bool|void|DWORD\s+WINAPI|std::string)\s+{re.escape(name)}\s*"
        rf"\([^;]*?\)\s*\{{",
        CPP,
        re.DOTALL,
    )
    if match is None:
        raise AssertionError(f"function definition not found: {name}")
    brace = CPP.index("{", match.start())
    depth = 0
    for index in range(brace, len(CPP)):
        char = CPP[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return CPP[brace + 1 : index]
    raise AssertionError(f"unterminated function: {name}")


class NativeLifecycleSourceContractTests(unittest.TestCase):
    def test_each_request_worker_installs_thread_local_seh_translation(self):
        worker = re.search(
            r"std::thread\(\[clientSocket,\s*admissionTicket\]\(\)\s*\{(?P<body>.*?)"
            r"bool\s+runningSlot",
            CPP,
            re.DOTALL,
        )
        self.assertIsNotNone(worker)
        self.assertIn("installSehTranslator();", worker.group("body"))

    def test_stopper_never_closes_sockets_owned_by_server_or_workers(self):
        body = _function_body("stopHttpServer")
        self.assertNotIn("closesocket(", body)
        self.assertIn("shutdown(activeClientSocket, SD_BOTH)", body)
        server = _function_body("HttpServerThread")
        self.assertIn("closesocket(listenSocket)", server)
        self.assertIn("ClientSocketGuard clientGuard(clientSocket)", server)

    def test_http_workers_stop_before_child_broker_teardown(self):
        body = _function_body("pluginStop")
        self.assertLess(body.index("stopHttpServer()"), body.index("childBrokerStop(true)"))

    def test_failed_bridge_start_fails_plugin_initialization(self):
        body = _function_body("pluginInit")
        failure = body.index('Failed to start HTTP server!')
        self.assertIn("unregisterCallbacks();", body[failure:])
        self.assertIn("unregisterCommands();", body[failure:])
        self.assertIn("return false;", body[failure:])

    def test_header_authentication_precedes_request_body_read(self):
        body = _function_body("readHttpRequest")
        auth = body.index("isBridgeAuthenticationValid(headerRequest)")
        body_loop = body.index("while (request.size() < needTotal)")
        self.assertLess(auth, body_loop)
        self.assertLess(body.index("isRequestOriginAllowed(headerRequest)"), body_loop)

    def test_http_request_cannot_self_stop_or_rebind_the_server(self):
        server = _function_body("HttpServerThread")
        self.assertIn("server_control_command_forbidden", server)
        self.assertIn('commandName == "httpserver"', server)
        self.assertIn('commandName == "httpport"', server)

    def test_http_request_cannot_unload_its_own_bridge(self):
        server = _function_body("HttpServerThread")
        for alias in ("plugunload", "pluginunload", "unloadplugin"):
            self.assertIn(f'commandName == "{alias}"', server)
        self.assertIn("bridge_self_unload_forbidden", server)

    def test_plugin_stop_rejects_reentrant_http_worker_unload(self):
        stop = _function_body("pluginStop")
        self.assertIn("g_insideHttpRequestWorker", stop)
        self.assertIn("return false", stop)
        self.assertIn("HttpRequestWorkerScope requestWorkerScope", CPP)

    def test_trace_callback_fails_closed_on_recorder_exception(self):
        callback = _function_body("debugSessionCallback")
        self.assertIn("case CB_TRACEEXECUTE:", callback)
        trace_case = callback[
            callback.index("case CB_TRACEEXECUTE:"):
            callback.index("case CB_INITDEBUG:")
        ]
        self.assertIn("try", trace_case)
        self.assertIn("callback_exception", trace_case)
        self.assertIn("g_nativeTrace.cv.notify_all()", trace_case)

    def test_native_provenance_and_dependency_download_are_reproducible(self):
        self.assertIn("MCP_CHILD_BROKER_CORE_SHA256", CMAKE)
        self.assertIn("MCP_CHILD_BROKER_HEADER_SHA256", CMAKE)
        self.assertIn("X64DBG_SDK_PINNED_SHA256", CMAKE)
        self.assertIn('EXPECTED_HASH "SHA256=${X64DBG_SDK_PINNED_SHA256}"', CMAKE)
        self.assertIn('file(LOCK "${X64DBG_DEPS_DIR}/.x64dbg-sdk.lock"', CMAKE)
        self.assertIn(
            "target_compile_options(bridge_core_native_tests PRIVATE /EHsc /W4 /WX)",
            CMAKE,
        )

    def test_superbuild_rechecks_both_architectures_after_source_changes(self):
        external_projects = re.findall(
            r"ExternalProject_Add\(plugin(?:32|64)(.*?)\n\s*\)",
            CMAKE,
            re.DOTALL,
        )
        self.assertEqual(len(external_projects), 2)
        for project in external_projects:
            self.assertRegex(project, r"\bBUILD_ALWAYS\s+1\b")


if __name__ == "__main__":
    unittest.main()
