"""Offline safety checks plus one opt-in live Qwen smoke for Qwen OpsPilot."""

from __future__ import annotations

import io
import hashlib
import json
import os
import socket
import ssl
import subprocess
import threading
import unittest
import urllib.error
import urllib.request
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch

import app


VALID_ENV = {
    "DASHSCOPE_API_KEY": "test-only-key",
    "DASHSCOPE_BASE_URL": "https://workspace-test.ap-southeast-1.maas.aliyuncs.com/compatible-mode/v1",
}


def expected_tool_calls() -> list[dict[str, object]]:
    return [
        {
            "id": f"call-{index}",
            "type": "function",
            "function": {"name": name, "arguments": json.dumps({"host": host})},
        }
        for index, (name, host) in enumerate(app.EXPECTED_TOOL_SEQUENCE, 1)
    ]


def valid_diagnosis() -> dict[str, object]:
    return {
        "observed": [
            {"statement": "Host A uses InteractiveToken.", "evidence_ids": ["task-a-logon-type"]},
            {
                "statement": "Host A runs interactively in session 1.",
                "evidence_ids": ["runtime-a-session-id", "runtime-a-interactive"],
            },
            {
                "statement": "Host B uses S4U in non-interactive session 0.",
                "evidence_ids": [
                    "task-b-logon-type",
                    "runtime-b-session-id",
                    "runtime-b-interactive",
                ],
            },
        ],
        "inferences": [
            {
                "statement": "Interactive logon and session behavior explains the visible window on Host A.",
                "evidence_ids": [
                    "task-a-logon-type",
                    "runtime-a-session-id",
                    "runtime-a-interactive",
                    "task-b-logon-type",
                    "runtime-b-session-id",
                ],
            }
        ],
        "root_cause": "Host A launches through an interactive logon in an interactive desktop session.",
        "confidence": "high",
        "remediation_status": "not_performed",
        "decisive_evidence_ids": [
            "task-a-logon-type",
            "runtime-a-session-id",
            "runtime-a-interactive",
        ],
        "ruled_out": [
            {
                "statement": "The shared hidden-window settings alone are insufficient because both hosts use them.",
                "evidence_ids": ["task-a-hidden", "task-b-hidden"],
            }
        ],
    }


def valid_model_messages() -> list[dict[str, object]]:
    return [
        {
            "content": json.dumps(
                {
                    "plan": [
                        {"action": "Confirm the reported symptom and scope."},
                        {"action": "Compare the scheduled task definitions."},
                        {"action": "Compare runtime session context."},
                        {"action": "Correlate evidence and identify the cause."},
                    ]
                }
            )
        },
        {"content": "", "tool_calls": expected_tool_calls()},
        {"content": json.dumps(valid_diagnosis())},
    ]


def collected_evidence() -> list[dict[str, object]]:
    fixture = app.load_fixture()
    evidence: list[dict[str, object]] = []
    for name, host in app.EXPECTED_TOOL_SEQUENCE:
        for record in app.execute_tool_call(name, {"host": host}, fixture)["evidence"]:
            normalized = deepcopy(record)
            normalized["host"] = host
            normalized["tool"] = name
            evidence.append(normalized)
    return evidence


def signed_run() -> dict[str, object]:
    with patch.dict(os.environ, VALID_ENV, clear=True), patch(
        "app.qwen_chat", side_effect=valid_model_messages()
    ):
        return app.run_investigation()


class QuietOpsPilotHandler(app.OpsPilotHandler):
    def log_message(self, format: str, *args: object) -> None:
        pass


class OpsPilotOfflineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = app.ThreadingHTTPServer(("127.0.0.1", 0), QuietOpsPilotHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever)
        cls.thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.thread.join()
        cls.server.server_close()

    def request_json(
        self,
        path: str,
        *,
        body: object | None = None,
        raw_body: bytes | None = None,
    ) -> tuple[int, dict[str, object]]:
        data = raw_body if raw_body is not None else (json.dumps(body).encode() if body is not None else None)
        request = urllib.request.Request(
            self.base_url + path,
            data=data,
            headers={"Content-Type": "application/json"} if data is not None else {},
            method="POST" if data is not None else "GET",
        )
        try:
            with urllib.request.urlopen(request, timeout=3) as response:
                return response.status, json.load(response)
        except urllib.error.HTTPError as error:
            return error.code, json.load(error)

    def request_raw(
        self,
        path: str,
        body: object,
    ) -> tuple[int, object, bytes]:
        request = urllib.request.Request(
            self.base_url + path,
            data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=3) as response:
                return response.status, response.headers, response.read()
        except urllib.error.HTTPError as error:
            return error.code, error.headers, error.read()

    def test_deployment_configuration_health_and_security_headers(self) -> None:
        deployment_secret = "phase3-stable-hmac-secret-32chars-minimum"
        with patch.dict(
            os.environ,
            {
                "OPSPILOT_HMAC_SECRET": deployment_secret,
                "OPSPILOT_BIND_HOST": "0.0.0.0",
                "FC_CUSTOM_LISTEN_PORT": "9000",
            },
            clear=True,
        ):
            self.assertEqual(hashlib.sha256(deployment_secret.encode()).digest(), app._load_approval_secret())
            self.assertEqual(("0.0.0.0", 9000), app.server_binding())

        with patch.dict(os.environ, {"OPSPILOT_HMAC_SECRET": "too-short"}, clear=True):
            with self.assertRaises(RuntimeError):
                app._load_approval_secret()
        with patch.dict(os.environ, {"OPSPILOT_BIND_HOST": "*"}, clear=True):
            with self.assertRaises(RuntimeError):
                app.server_binding()
        with patch.dict(os.environ, {"PORT": "70000"}, clear=True):
            with self.assertRaises(RuntimeError):
                app.server_binding()

        request = urllib.request.Request(self.base_url + "/api/health", method="GET")
        with urllib.request.urlopen(request, timeout=3) as response:
            payload = json.load(response)
            self.assertEqual(200, response.status)
            self.assertEqual("ok", payload["status"])
            self.assertEqual("Qwen OpsPilot", payload["service"])
            self.assertEqual("nosniff", response.headers["X-Content-Type-Options"])
            self.assertEqual("DENY", response.headers["X-Frame-Options"])
            self.assertIn("default-src 'self'", response.headers["Content-Security-Policy"])
            self.assertEqual(app.PUBLIC_APP_ORIGIN, response.headers["Access-Control-Allow-Origin"])

        preflight = urllib.request.Request(
            self.base_url + "/api/run",
            headers={
                "Origin": app.PUBLIC_APP_ORIGIN,
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "content-type",
            },
            method="OPTIONS",
        )
        with urllib.request.urlopen(preflight, timeout=3) as response:
            self.assertEqual(204, response.status)
            self.assertEqual(app.PUBLIC_APP_ORIGIN, response.headers["Access-Control-Allow-Origin"])
            self.assertIn("POST", response.headers["Access-Control-Allow-Methods"])
            self.assertEqual("Content-Type", response.headers["Access-Control-Allow-Headers"])

    def test_fixture_reset_hash_ids_sources_and_ambiguity(self) -> None:
        first = app.load_fixture()
        second = app.load_fixture()
        first_records = [
            record
            for host in first["hosts"].values()
            for group in ("task_definition", "runtime_context", "launcher_settings")
            for record in host[group]
        ]
        second_records = [
            record
            for host in second["hosts"].values()
            for group in ("task_definition", "runtime_context", "launcher_settings")
            for record in host[group]
        ]
        self.assertEqual("1.0", first["fixture_version"])
        self.assertEqual(app.fixture_hash(first), app.fixture_hash(second))
        self.assertEqual([item["id"] for item in first_records], [item["id"] for item in second_records])
        self.assertEqual([item["source"] for item in first_records], [item["source"] for item in second_records])
        self.assertEqual(len(first_records), len({item["id"] for item in first_records}))
        self.assertFalse(any(term in first["symptom"] for term in ("InteractiveToken", "S4U", "Session 0", "root cause")))

    def test_all_allowed_tools_for_both_hosts_are_read_only(self) -> None:
        before = app.fixture_hash(app.load_fixture())
        for name in app.TOOL_HANDLERS:
            for host in ("A", "B"):
                result = app.execute_tool_call(name, {"host": host})
                self.assertEqual("ALLOWED", result["status"])
                self.assertEqual(host, result["host"])
                self.assertTrue(result["evidence"])
        self.assertEqual(before, app.fixture_hash(app.load_fixture()))

    def test_task_and_launcher_evidence_contains_required_fields(self) -> None:
        task = app.execute_tool_call("compare_task_definitions", {"host": "A"})["evidence"]
        launcher = app.execute_tool_call("compare_launcher_settings", {"host": "A"})["evidence"]
        self.assertEqual(
            {"logon_type", "state", "last_task_result", "executable", "arguments", "hidden", "window_style"},
            {item["field"] for item in task},
        )
        self.assertEqual({"executable", "arguments", "window_style"}, {item["field"] for item in launcher})
        self.assertIn("-WindowStyle Hidden", next(item["value"] for item in task if item["field"] == "arguments"))

    def test_policy_denies_unknown_invalid_and_smuggled_arguments(self) -> None:
        before = app.fixture_hash(app.load_fixture())
        cases = [
            ("run_shell", {"command": "whoami"}),
            ("compare_task_definitions", {"host": "C"}),
            ("compare_task_definitions", {}),
            ("compare_task_definitions", {"host": "A", "extra": True}),
            ("compare_task_definitions", {"host": "A", "command": "whoami"}),
            ("compare_task_definitions", {"host": "A", "path": "C:\\temp"}),
            ("compare_task_definitions", {"host": "A", "url": "https://example.invalid"}),
            ("compare_task_definitions", "not-json"),
            ([], {"host": "A"}),
            ({}, {"host": "A"}),
            (None, {"host": "A"}),
            ("compare_task_definitions", {"host": []}),
            ("compare_task_definitions", {"host": {}}),
            ("compare_task_definitions", {"host": None}),
        ]
        for name, arguments in cases:
            with self.subTest(name=name, arguments=arguments):
                self.assertEqual("BLOCKED_BY_POLICY", app.execute_tool_call(name, arguments)["status"])
        self.assertEqual(before, app.fixture_hash(app.load_fixture()))

    def test_tool_registry_and_schemas_are_closed(self) -> None:
        self.assertEqual(
            {
                "compare_task_definitions",
                "compare_runtime_context",
                "compare_launcher_settings",
            },
            set(app.TOOL_HANDLERS),
        )
        self.assertEqual(3, len(app.TOOL_SCHEMAS))
        for schema in app.TOOL_SCHEMAS:
            parameters = schema["function"]["parameters"]
            self.assertEqual(["host"], parameters["required"])
            self.assertFalse(parameters["additionalProperties"])
            self.assertEqual(["A", "B"], parameters["properties"]["host"]["enum"])

    def test_missing_key_or_workspace_base_returns_503_without_fallback(self) -> None:
        cases = ({}, {"DASHSCOPE_API_KEY": "test-only-key"})
        for environment in cases:
            with self.subTest(environment=set(environment)), patch.dict(os.environ, environment, clear=True):
                status, payload = self.request_json(
                    "/api/run", body={"incident_id": "watchdog-window-flash"}
                )
                self.assertEqual(503, status)
                self.assertEqual("failed", payload["status"])
                self.assertEqual("QWEN_NOT_CONFIGURED", payload["error"]["code"])
                self.assertNotIn("plan", payload)
                self.assertNotIn("diagnosis", payload)

    def test_workspace_base_rejects_malformed_and_near_match_urls(self) -> None:
        qwen_cloud_base = "https://dashscope-intl.aliyuncs.com/compatible-mode/v1"
        with patch.dict(
            os.environ,
            {"DASHSCOPE_API_KEY": "test-only-key", "DASHSCOPE_BASE_URL": qwen_cloud_base},
            clear=True,
        ):
            self.assertEqual(qwen_cloud_base, app._qwen_configuration()[1])

        invalid_urls = (
            "https://[broken/compatible-mode/v1",
            "https://workspace-test.ap-southeast-1.maas.aliyuncs.com:text/compatible-mode/v1",
            "https://workspace-test.ap-southeast-1.maas.aliyuncs.com:70000/compatible-mode/v1",
            "https://user:pass@workspace-test.ap-southeast-1.maas.aliyuncs.com/compatible-mode/v1",
            "https://workspace-test.ap-southeast-1.maas.aliyuncs.com/compatible-mode/v1?query=1",
            "https://workspace-test.ap-southeast-1.maas.aliyuncs.com/compatible-mode/v1#fragment",
            "https://workspace-test.ap-southeast-1.maas.aliyuncs.com.evil.invalid/compatible-mode/v1",
            "https://dashscope-intl.aliyuncs.com.evil.invalid/compatible-mode/v1",
        )
        for base_url in invalid_urls:
            with self.subTest(base_url=base_url), patch.dict(
                os.environ,
                {"DASHSCOPE_API_KEY": "test-only-key", "DASHSCOPE_BASE_URL": base_url},
                clear=True,
            ):
                with self.assertRaises(app.QwenError) as error:
                    app._qwen_configuration()
                self.assertEqual("QWEN_NOT_CONFIGURED", error.exception.code)

    def test_request_size_and_concurrent_run_are_rejected_before_qwen(self) -> None:
        status, payload = self.request_json("/api/policy-check", raw_body=b'"' + b"x" * (app.MAX_REQUEST_BYTES + 1) + b'"')
        self.assertEqual(413, status)
        self.assertEqual("REQUEST_TOO_LARGE", payload["error"]["code"])

        self.assertTrue(app.RUN_LOCK.acquire(blocking=False))
        try:
            with patch("app.run_investigation") as run_mock:
                status, payload = self.request_json(
                    "/api/run", body={"incident_id": "watchdog-window-flash"}
                )
                self.assertEqual(429, status)
                self.assertEqual("RUN_IN_PROGRESS", payload["error"]["code"])
                run_mock.assert_not_called()
        finally:
            app.RUN_LOCK.release()

    def test_run_endpoint_releases_lock_after_success_and_failure(self) -> None:
        outcomes = (
            ({"status": "succeeded", "run_id": "test-run"}, 200, None),
            (app.QwenError("QWEN_PROVIDER_ERROR", "provider failed"), 502, "QWEN_PROVIDER_ERROR"),
        )
        for outcome, expected_status, expected_code in outcomes:
            effect = outcome if isinstance(outcome, BaseException) else None
            with self.subTest(expected_status=expected_status), patch(
                "app.run_investigation", side_effect=effect, return_value=None if effect else outcome
            ):
                status, payload = self.request_json(
                    "/api/run", body={"incident_id": "watchdog-window-flash"}
                )
            self.assertEqual(expected_status, status)
            if expected_code:
                self.assertEqual(expected_code, payload["error"]["code"])
            self.assertTrue(app.RUN_LOCK.acquire(blocking=False))
            app.RUN_LOCK.release()

    def test_mocked_run_orders_plan_then_exact_tools_and_respects_caps(self) -> None:
        messages = valid_model_messages()
        with patch.dict(os.environ, VALID_ENV, clear=True), patch(
            "app.qwen_chat", side_effect=messages
        ) as mocked:
            result = app.run_investigation()
        self.assertEqual(3, mocked.call_count)
        self.assertEqual(3, result["model_response_count"])
        self.assertEqual(4, result["processed_tool_calls"])
        self.assertEqual("plan", result["events"][0]["type"])
        self.assertEqual(
            list(app.EXPECTED_TOOL_SEQUENCE),
            [(call["name"], call["host"]) for call in result["tool_trace"]],
        )
        self.assertEqual(["plan", "tool", "tool", "tool", "tool", "diagnosis"], [event["type"] for event in result["events"]])
        planning_messages = mocked.call_args_list[0].args[0]
        self.assertEqual(app.load_fixture()["symptom"], planning_messages[1]["content"])

    def test_tool_call_envelopes_require_function_type_and_unique_ids(self) -> None:
        malformed_batches = []
        wrong_type = expected_tool_calls()
        wrong_type[-1]["type"] = "not-function"
        malformed_batches.append(wrong_type)
        missing_type = expected_tool_calls()
        missing_type[-1].pop("type")
        malformed_batches.append(missing_type)
        non_object = expected_tool_calls()
        non_object[-1] = []
        malformed_batches.append(non_object)
        duplicate_ids = expected_tool_calls()
        duplicate_ids[-1]["id"] = duplicate_ids[0]["id"]
        malformed_batches.append(duplicate_ids)

        for raw_calls in malformed_batches:
            with self.subTest(raw_calls=raw_calls), patch(
                "app.qwen_chat", return_value={"content": "", "tool_calls": raw_calls}
            ), patch("app.execute_tool_call") as execute:
                with self.assertRaises(app.QwenError) as error:
                    app.collect_diagnosis(
                        "symptom",
                        [{"id": "plan-1", "action": "inspect"}],
                        app.load_fixture(),
                    )
                self.assertEqual("QWEN_PROVIDER_ERROR", error.exception.code)
                execute.assert_not_called()

    def test_outbound_requests_use_deterministic_safe_model_contract(self) -> None:
        responses = [
            io.BytesIO(json.dumps({"choices": [{"message": message}]}).encode())
            for message in valid_model_messages()
        ]
        with patch.dict(os.environ, VALID_ENV, clear=True), patch.object(
            app.QWEN_OPENER, "open", side_effect=responses
        ) as opened:
            result = app.run_investigation()

        self.assertEqual("succeeded", result["status"])
        self.assertEqual(3, opened.call_count)
        requests = [call.args[0] for call in opened.call_args_list]
        payloads = [json.loads(request.data) for request in requests]
        self.assertTrue(all(request.full_url == VALID_ENV["DASHSCOPE_BASE_URL"] + "/chat/completions" for request in requests))
        self.assertTrue(all(request.get_header("Authorization") == "Bearer test-only-key" for request in requests))
        self.assertTrue(all(payload["model"] == app.DEFAULT_MODEL for payload in payloads))
        self.assertTrue(all(payload["enable_thinking"] is False for payload in payloads))
        self.assertTrue(all(payload["temperature"] == 0 for payload in payloads))
        self.assertEqual({"type": "json_object"}, payloads[0]["response_format"])
        self.assertEqual(app.TOOL_SCHEMAS, payloads[1]["tools"])
        self.assertTrue(payloads[1]["parallel_tool_calls"])
        self.assertIn("single response", payloads[1]["messages"][0]["content"])
        self.assertIn("parallel tool calls simultaneously", payloads[1]["messages"][0]["content"])
        self.assertEqual({"type": "json_object"}, payloads[2]["response_format"])
        self.assertIn("include a ruled_out item", payloads[2]["messages"][-1]["content"])

    def test_excess_tool_and_model_responses_are_blocked(self) -> None:
        excessive_calls = expected_tool_calls() + [
            {
                "id": "call-5",
                "type": "function",
                "function": {"name": "compare_launcher_settings", "arguments": '{"host":"A"}'},
            }
        ]
        with patch("app.qwen_chat", return_value={"content": "", "tool_calls": excessive_calls}):
            with self.assertRaisesRegex(app.QwenError, "four-call") as error:
                app.collect_diagnosis("symptom", [{"id": "plan-1", "action": "inspect"}], app.load_fixture())
        self.assertEqual("TOOL_LIMIT_EXCEEDED", error.exception.code)

        with patch.dict(os.environ, VALID_ENV, clear=True), patch(
            "app.create_plan", return_value=[{"id": "plan-1", "action": "inspect"}]
        ), patch(
            "app.collect_diagnosis",
            return_value={
                "tool_trace": [],
                "evidence": [],
                "diagnosis": {},
                "model_responses": 3,
                "processed_tool_calls": 0,
            },
        ):
            with self.assertRaisesRegex(app.QwenError, "three-response") as error:
                app.run_investigation()
        self.assertEqual("MODEL_LIMIT_EXCEEDED", error.exception.code)

    def test_qwen_retry_is_bounded_and_only_for_transient_failures(self) -> None:
        def success() -> io.BytesIO:
            return io.BytesIO(json.dumps({"choices": [{"message": {"content": "{}"}}]}).encode())

        transient_cases = (
            urllib.error.HTTPError("https://provider.invalid", 429, "busy", {"Retry-After": "1.5"}, None),
            urllib.error.HTTPError("https://provider.invalid", 503, "busy", {}, None),
            urllib.error.URLError(socket.timeout("temporary")),
        )
        for transient in transient_cases:
            with self.subTest(transient=transient), patch.dict(os.environ, VALID_ENV, clear=True), patch.object(
                app.QWEN_OPENER, "open", side_effect=[transient, success()]
            ) as opened, patch("app.time.sleep") as slept:
                self.assertEqual({"content": "{}"}, app.qwen_chat([{"role": "user", "content": "JSON"}]))
                self.assertEqual(2, opened.call_count)
                if isinstance(transient, urllib.error.HTTPError) and transient.code == 429:
                    slept.assert_called_once_with(1.5)
                else:
                    slept.assert_not_called()

        permanent_cases = (
            urllib.error.HTTPError("https://provider.invalid", 400, "bad", {}, None),
            urllib.error.URLError(ssl.SSLCertVerificationError("untrusted certificate")),
            urllib.error.URLError("malformed URL"),
        )
        for permanent in permanent_cases:
            with self.subTest(permanent=permanent), patch.dict(os.environ, VALID_ENV, clear=True), patch.object(
                app.QWEN_OPENER, "open", side_effect=permanent
            ) as opened:
                with self.assertRaises(app.QwenError):
                    app.qwen_chat([{"role": "user", "content": "JSON"}])
                self.assertEqual(1, opened.call_count)

    def test_qwen_rejects_redirects_and_malformed_provider_shapes(self) -> None:
        malformed = (None, [], {}, {"choices": []}, {"choices": [None]}, {"choices": [{"message": []}]})
        for document in malformed:
            response = io.BytesIO(json.dumps(document).encode())
            with self.subTest(document=document), patch.dict(os.environ, VALID_ENV, clear=True), patch.object(
                app.QWEN_OPENER, "open", return_value=response
            ):
                with self.assertRaises(app.QwenError) as error:
                    app.qwen_chat([{"role": "user", "content": "JSON"}])
                self.assertEqual("QWEN_PROVIDER_ERROR", error.exception.code)

        requests_seen: list[tuple[str, str | None]] = []

        class RedirectHandler(app.BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: object) -> None:
                pass

            def do_GET(self) -> None:
                requests_seen.append((self.path, self.headers.get("Authorization")))
                if self.path == "/start":
                    self.send_response(302)
                    self.send_header("Location", "/target")
                    self.end_headers()
                else:
                    self.send_response(200)
                    self.end_headers()

        redirect_server = app.ThreadingHTTPServer(("127.0.0.1", 0), RedirectHandler)
        redirect_thread = threading.Thread(target=redirect_server.serve_forever)
        redirect_thread.start()
        try:
            request = urllib.request.Request(
                f"http://127.0.0.1:{redirect_server.server_port}/start",
                headers={"Authorization": "Bearer must-not-leak"},
            )
            with self.assertRaises(urllib.error.HTTPError) as error:
                app.QWEN_OPENER.open(request, timeout=3)
            self.assertEqual(302, error.exception.code)
            error.exception.close()
            self.assertEqual([("/start", "Bearer must-not-leak")], requests_seen)
        finally:
            redirect_server.shutdown()
            redirect_thread.join()
            redirect_server.server_close()

        redirect = urllib.error.HTTPError(
            VALID_ENV["DASHSCOPE_BASE_URL"] + "/chat/completions",
            302,
            "redirect",
            {"Location": "https://evil.invalid/steal"},
            None,
        )
        with patch.dict(os.environ, VALID_ENV, clear=True), patch.object(
            app.QWEN_OPENER, "open", side_effect=redirect
        ) as opened:
            with self.assertRaises(app.QwenError):
                app.qwen_chat([{"role": "user", "content": "JSON"}])
            self.assertEqual(1, opened.call_count)

    def test_untrusted_json_boundaries_reject_nonstandard_and_recursive_values(self) -> None:
        invalid_provider_documents = (
            b'{"choices":[{"message":{"content":"{}"}}],"invalid":NaN}',
            ("[" * 1100 + "0" + "]" * 1100).encode(),
        )
        for document in invalid_provider_documents:
            with self.subTest(document=document[:40]), patch.dict(os.environ, VALID_ENV, clear=True), patch.object(
                app.QWEN_OPENER, "open", return_value=io.BytesIO(document)
            ):
                with self.assertRaises(app.QwenError) as error:
                    app.qwen_chat([{"role": "user", "content": "JSON"}])
                self.assertEqual("QWEN_PROVIDER_ERROR", error.exception.code)

        deep_json = "[" * 1100 + "0" + "]" * 1100
        for content in ('{"invalid":Infinity}', deep_json):
            with self.subTest(content=content[:40]), self.assertRaises(app.QwenError):
                app._message_json({"content": content}, "diagnosis")

        for arguments in ('{"host":NaN}', deep_json):
            with self.subTest(arguments=arguments[:40]):
                result = app.execute_tool_call("compare_task_definitions", arguments)
                self.assertEqual("BLOCKED_BY_POLICY", result["status"])

        for raw_body in (b'{"incident_id":NaN}', deep_json.encode()):
            with self.subTest(raw_body=raw_body[:40]):
                status, payload = self.request_json("/api/run", raw_body=raw_body)
                self.assertEqual(400, status)
                self.assertEqual("INVALID_JSON", payload["error"]["code"])

    def test_http_serialization_never_emits_nonfinite_json_or_disconnects(self) -> None:
        evidence = collected_evidence()
        for confidence in (float("nan"), float("inf"), float("-inf"), True, "", [], {}):
            with self.subTest(confidence=confidence):
                diagnosis = valid_diagnosis()
                diagnosis["confidence"] = confidence
                with self.assertRaises(app.DiagnosisValidationError):
                    app.validate_diagnosis(diagnosis, evidence)

        messages = valid_model_messages()
        messages[-1] = {"content": json.dumps({**valid_diagnosis(), "confidence": float("nan")})}
        with patch.dict(os.environ, VALID_ENV, clear=True), patch("app.qwen_chat", side_effect=messages):
            status, payload = self.request_json(
                "/api/run", body={"incident_id": "watchdog-window-flash"}
            )
        self.assertEqual(502, status)
        self.assertEqual("QWEN_PROVIDER_ERROR", payload["error"]["code"])

        with patch("app.run_investigation", return_value={"confidence": float("inf")}):
            status, payload = self.request_json(
                "/api/run", body={"incident_id": "watchdog-window-flash"}
            )
        self.assertEqual(500, status)
        self.assertEqual("SERVER_ERROR", payload["error"]["code"])

        self.assertEqual('"\\ud800"', app.canonical_json("\ud800"))

    def test_diagnosis_requires_current_citations_and_fact_inference_separation(self) -> None:
        evidence = collected_evidence()
        diagnosis = valid_diagnosis()
        validated = app.validate_diagnosis(diagnosis, evidence)
        self.assertEqual(len(evidence), len(validated["observed"]))
        self.assertEqual(
            {item["id"] for item in evidence},
            {item["evidence_ids"][0] for item in validated["observed"]},
        )

        invented = deepcopy(diagnosis)
        invented["observed"] = [
            {"statement": "Host A downloaded and executed malware.", "evidence_ids": ["task-a-logon-type"]}
        ]
        normalized = app.validate_diagnosis(invented, evidence)
        self.assertNotIn("malware", " ".join(item["statement"] for item in normalized["observed"]).lower())

        missing_inferences = deepcopy(diagnosis)
        missing_inferences["inferences"] = []
        with self.assertRaises(app.DiagnosisValidationError):
            app.validate_diagnosis(missing_inferences, evidence)

        uncited_ruled_out = deepcopy(diagnosis)
        uncited_ruled_out["ruled_out"] = ["Hidden settings are insufficient."]
        with self.assertRaises(app.DiagnosisValidationError):
            app.validate_diagnosis(uncited_ruled_out, evidence)

        unrelated_ruled_out = deepcopy(diagnosis)
        unrelated_ruled_out["ruled_out"][0]["evidence_ids"] = ["task-a-logon-type", "task-b-logon-type"]
        with self.assertRaises(app.DiagnosisValidationError):
            app.validate_diagnosis(unrelated_ruled_out, evidence)

        citation_fields = (
            ("inferences", lambda value, citations: value["inferences"][0].__setitem__("evidence_ids", citations)),
            ("ruled_out", lambda value, citations: value["ruled_out"][0].__setitem__("evidence_ids", citations)),
            ("decisive", lambda value, citations: value.__setitem__("decisive_evidence_ids", citations)),
        )
        invalid_citations = ([[]], [{}], [None], ["task-a-logon-type", "task-a-logon-type"])
        for field, set_citations in citation_fields:
            for citations in invalid_citations:
                with self.subTest(field=field, citations=citations):
                    malformed = valid_diagnosis()
                    set_citations(malformed, citations)
                    with self.assertRaises(app.DiagnosisValidationError):
                        app.validate_diagnosis(malformed, evidence)

        messages = valid_model_messages()
        malformed_diagnosis = valid_diagnosis()
        malformed_diagnosis["inferences"][0]["evidence_ids"] = [[]]
        messages[-1] = {"content": json.dumps(malformed_diagnosis)}
        with patch.dict(os.environ, VALID_ENV, clear=True), patch("app.qwen_chat", side_effect=messages):
            status, payload = self.request_json(
                "/api/run", body={"incident_id": "watchdog-window-flash"}
            )
        self.assertEqual(502, status)
        self.assertEqual("QWEN_PROVIDER_ERROR", payload["error"]["code"])

    def test_diagnosis_rejects_non_decisive_or_false_success_narratives(self) -> None:
        evidence = collected_evidence()
        diagnosis = valid_diagnosis()
        diagnosis["decisive_evidence_ids"] = ["task-a-logon-type"]
        with self.assertRaises(app.DiagnosisValidationError):
            app.validate_diagnosis(diagnosis, evidence)

        for remediation_status in (None, "succeeded", True):
            with self.subTest(remediation_status=remediation_status):
                invalid_status = valid_diagnosis()
                if remediation_status is None:
                    invalid_status.pop("remediation_status")
                else:
                    invalid_status["remediation_status"] = remediation_status
                with self.assertRaises(app.DiagnosisValidationError):
                    app.validate_diagnosis(invalid_status, evidence)

        false_success_claims = (
            ("root_cause", "The problem is fixed"),
            ("root_cause", "The issue is now resolved"),
            ("inferences", "Remediation was successful"),
            ("inferences", "Host A no longer flashes"),
            ("ruled_out", "The incident has been remediated"),
            ("ruled_out", "The change succeeded"),
        )
        for field, claim in false_success_claims:
            with self.subTest(field=field, claim=claim):
                false_success = valid_diagnosis()
                if field == "root_cause":
                    false_success[field] += f" {claim}."
                else:
                    false_success[field][0]["statement"] += f" {claim}."
                with self.assertRaises(app.DiagnosisValidationError):
                    app.validate_diagnosis(false_success, evidence)

        legitimate = valid_diagnosis()
        legitimate["inferences"][0]["statement"] += (
            " The scheduled task succeeded, so an execution failure is not the cause."
        )
        self.assertEqual("not_performed", app.validate_diagnosis(legitimate, evidence)["remediation_status"])

    def test_phase2_proposal_approval_rejection_and_idempotence(self) -> None:
        source_bytes = app.FIXTURE_PATH.read_bytes()
        source_hash = app.fixture_hash(app.load_fixture())
        run = signed_run()
        proposal = run["proposal"]

        self.assertEqual("Simulated", proposal["label"])
        self.assertIn("InteractiveToken", app.canonical_json(proposal))
        self.assertIn("S4U", app.canonical_json(proposal))
        for field in (
            "expected_outcome",
            "changes",
            "prerequisites",
            "limitations",
            "rollback",
            "verification_checks",
        ):
            self.assertTrue(proposal[field], field)
        self.assertEqual(app.value_hash(proposal), run["proposal_hash"])
        self.assertEqual(app.value_hash({key: run[key] for key in app.RUN_CORE_KEYS}), run["run_hash"])
        self.assertGreater(run["approval"]["expires_at"], int(app.time.time()))

        status, approved = self.request_json("/api/approve", body={"run": run})
        self.assertEqual(200, status)
        self.assertEqual("approved", approved["decision"])
        self.assertTrue(approved["applied"])
        self.assertTrue(approved["simulation"])
        self.assertEqual(app.SIMULATION_LABEL, approved["simulation_label"])
        self.assertEqual(
            {
                "logon_type": "InteractiveToken",
                "session_id": 1,
                "interactive": True,
                "state": "Ready",
                "last_task_result": 0,
            },
            approved["before"],
        )
        self.assertEqual(
            {
                "logon_type": "S4U",
                "session_id": 0,
                "interactive": False,
                "state": "Ready",
                "last_task_result": 0,
            },
            approved["after"],
        )
        self.assertTrue(approved["verification"]["success"])
        self.assertEqual(5, len(approved["verification"]["checks"]))
        self.assertTrue(all(check["passed"] for check in approved["verification"]["checks"]))

        repeat_status, repeated = self.request_json("/api/approve", body={"run": run})
        self.assertEqual(200, repeat_status)
        self.assertEqual(approved, repeated)

        reject_status, rejected = self.request_json("/api/reject", body={"run": run})
        self.assertEqual(200, reject_status)
        self.assertEqual("rejected", rejected["decision"])
        self.assertFalse(rejected["applied"])
        self.assertEqual(rejected["before"], rejected["after"])
        self.assertFalse(rejected["verification"]["success"])
        self.assertEqual(source_hash, app.fixture_hash(app.load_fixture()))
        self.assertEqual(source_bytes, app.FIXTURE_PATH.read_bytes())

    def test_phase2_tampering_expiry_and_malformed_requests_fail_closed(self) -> None:
        source_bytes = app.FIXTURE_PATH.read_bytes()
        run = signed_run()

        token_tamper = deepcopy(run)
        encoded, signature = token_tamper["approval"]["token"].split(".")
        signature = ("A" if signature[0] != "A" else "B") + signature[1:]
        token_tamper["approval"]["token"] = f"{encoded}.{signature}"

        cases = []
        run_tamper = deepcopy(run)
        run_tamper["diagnosis"]["root_cause"] = "Changed after signing."
        cases.append(run_tamper)
        proposal_tamper = deepcopy(run)
        proposal_tamper["proposal"]["title"] = "Changed proposal"
        cases.append(proposal_tamper)
        version_tamper = deepcopy(run)
        version_tamper["fixture_version"] = "2.0"
        cases.append(version_tamper)
        fixture_hash_tamper = deepcopy(run)
        fixture_hash_tamper["fixture_hash"] = "0" * 64
        cases.append(fixture_hash_tamper)
        proposal_hash_tamper = deepcopy(run)
        proposal_hash_tamper["proposal_hash"] = "0" * 64
        cases.append(proposal_hash_tamper)
        cases.append(token_tamper)

        for altered in cases:
            with self.subTest(changed=set(key for key in altered if altered[key] != run.get(key))):
                status, payload = self.request_json("/api/approve", body={"run": altered})
                self.assertEqual(403, status)
                self.assertFalse(payload["decision"]["applied"])
                self.assertEqual(payload["decision"]["before"], payload["decision"]["after"])

        with patch("app.time.time", return_value=run["approval"]["expires_at"] + 1):
            status, payload = self.request_json("/api/approve", body={"run": run})
        self.assertEqual(403, status)
        self.assertEqual("TOKEN_EXPIRED", payload["error"]["code"])
        self.assertEqual(payload["decision"]["before"], payload["decision"]["after"])

        status, payload = self.request_json("/api/approve", body={"run": run, "extra": True})
        self.assertEqual(400, status)
        self.assertEqual(payload["decision"]["before"], payload["decision"]["after"])
        status, payload = self.request_json("/api/approve", raw_body=b"not-json")
        self.assertEqual(400, status)
        self.assertEqual(payload["decision"]["before"], payload["decision"]["after"])
        self.assertEqual(source_bytes, app.FIXTURE_PATH.read_bytes())

    def test_phase2_each_wrong_after_value_prevents_success(self) -> None:
        clone, _, _, verification = app.apply_simulated_remediation(
            app.load_fixture(),
            app.build_simulated_proposal(),
        )
        self.assertTrue(verification["success"])
        corruptions = (
            ("task_definition", "logon_type", "InteractiveToken"),
            ("runtime_context", "session_id", 1),
            ("runtime_context", "interactive", True),
            ("task_definition", "state", "Running"),
            ("task_definition", "last_task_result", 1),
        )
        for group, field, value in corruptions:
            corrupted = deepcopy(clone)
            record = next(item for item in corrupted["hosts"]["A"][group] if item["field"] == field)
            record["value"] = value
            with self.subTest(field=field):
                result = app.verify_simulated_remediation(corrupted)
                self.assertFalse(result["success"])
                self.assertFalse(next(check for check in result["checks"] if check["actual"] == value or check["id"].endswith(field.replace("_", "-")))["passed"])

    def test_phase2_report_is_complete_safe_and_integrity_checked(self) -> None:
        run = signed_run()
        approve_status, approved = self.request_json("/api/approve", body={"run": run})
        self.assertEqual(200, approve_status)
        status, headers, body = self.request_raw(
            "/api/report",
            {"run": run, "decision": approved},
        )
        report = body.decode("utf-8")
        self.assertEqual(200, status)
        self.assertEqual("text/markdown", headers.get_content_type())
        self.assertIn("attachment", headers["Content-Disposition"])
        for heading in (
            "Symptom",
            "Qwen provenance",
            "Investigation plan",
            "Tool trace",
            "Evidence",
            "Diagnosis",
            "Simulated proposal",
            "Integrity hashes and expiry",
            "Approval decision",
            "Before state",
            "After state",
            "Deterministic verification",
            "Rollback",
        ):
            self.assertIn(f"## {heading}", report)
        self.assertGreaterEqual(report.count(app.SIMULATION_LABEL), 2)
        self.assertNotIn(run["approval"]["token"], report)
        self.assertNotIn(approved["decision_token"], report)

        hostile_core = {key: deepcopy(run[key]) for key in app.RUN_CORE_KEYS}
        hostile = "# forged heading\n[click](https://evil.invalid)\n```html"
        hostile_core["diagnosis"]["root_cause"] = hostile
        fixture = app.load_fixture()
        proposal = app.build_simulated_proposal()
        capability = app.create_approval_capability(hostile_core, fixture, proposal)
        hostile_run = {
            **hostile_core,
            "proposal": proposal,
            "proposal_hash": capability["proposal_hash"],
            "run_hash": capability["run_hash"],
            "approval": capability["approval"],
        }
        core, validated_proposal, validated_fixture = app._validate_run_envelope(
            hostile_run,
            enforce_approval_expiry=True,
        )
        hostile_decision = app._issue_decision(
            hostile_run,
            core,
            validated_proposal,
            validated_fixture,
            "approved",
        )
        status, _, body = self.request_raw(
            "/api/report",
            {"run": hostile_run, "decision": hostile_decision},
        )
        hostile_report = body.decode("utf-8")
        self.assertEqual(200, status)
        self.assertNotIn("\n# forged heading", hostile_report)
        self.assertIn("# forged heading\\n[click]", hostile_report)

        tampered_decision = deepcopy(approved)
        tampered_decision["after"]["session_id"] = 1
        status, _, body = self.request_raw(
            "/api/report",
            {"run": run, "decision": tampered_decision},
        )
        self.assertEqual(403, status)
        self.assertEqual("DECISION_TAMPERED", json.loads(body)["error"]["code"])

    def test_browser_static_guard_avoids_html_sinks(self) -> None:
        source = Path("static/app.js").read_text(encoding="utf-8")
        html = Path("static/index.html").read_text(encoding="utf-8")
        public_html = Path("docs/index.html").read_text(encoding="utf-8")
        for unsafe_sink in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write"):
            self.assertNotIn(unsafe_sink, source)
        self.assertIn("textContent", source)
        self.assertIn("apiUrl", source)
        for endpoint in ("/api/approve", "/api/reject", "/api/report"):
            self.assertIn(endpoint, source)
        self.assertIn("response.blob()", source)
        for control in ("approve-button", "reject-button", "report-button"):
            self.assertIn(f'id="{control}"', html)
            self.assertIn(f'id="{control}"', public_html)
        self.assertGreaterEqual(html.count(" disabled"), 3)
        self.assertIn("https://qwen-opspilot-monmjgpcrk.ap-southeast-1.fcapp.run", public_html)
        self.assertNotIn("DASHSCOPE_API_KEY", public_html)

    def test_browser_runtime_handles_reset_races_hashes_and_hostile_text(self) -> None:
        smoke = r"""
const assert = require("assert/strict");
const fs = require("fs");
const vm = require("vm");

class Element {
  constructor(id = null) {
    this.id = id;
    this.textContent = "";
    this.dataset = {};
    this.children = [];
    this.disabled = false;
    this.hidden = false;
    this.listeners = {};
    this.href = "";
    this.download = "";
  }

  replaceChildren(...children) {
    this.children = children;
    this.textContent = "";
  }

  append(...children) {
    this.children.push(...children);
  }

  addEventListener(type, listener) {
    this.listeners[type] = listener;
  }

  click() {
    if (!this.disabled) {
      return this.listeners.click?.();
    }
  }

  remove() {}
}

const ids = [
  "status", "symptom", "fixture-hash", "host-a", "host-b", "provenance",
  "timeline", "plan", "tool-trace", "observed", "inferences", "root-cause",
  "confidence", "decisive-evidence", "ruled-out", "policy-result",
  "load-button", "run-button", "policy-button", "proposal-section",
  "simulation-label", "proposal-name", "proposal-outcome", "proposal-changes",
  "proposal-prerequisites", "proposal-limitations", "proposal-rollback",
  "proposal-checks", "run-hash", "proposal-hash", "approval-expiry",
  "approve-button", "reject-button", "decision-section", "decision-label",
  "decision-summary", "before-state", "after-state", "verification-results",
  "report-button",
];
const elements = Object.fromEntries(ids.map((id) => [id, new Element(id)]));
global.document = {
  getElementById: (id) => elements[id],
  createElement: () => new Element(),
  body: new Element("body"),
};
global.URL = {
  createObjectURL: () => "blob:test",
  revokeObjectURL: () => {},
};

const pending = [];
global.fetch = (url, options = {}) => {
  let resolve;
  let reject;
  const promise = new Promise((onResolve, onReject) => {
    resolve = onResolve;
    reject = onReject;
  });
  pending.push({
    url,
    options,
    resolve: (payload) => resolve({
      ok: true,
      json: async () => payload,
      blob: async () => ({ payload }),
    }),
    reject,
  });
  return promise;
};

const flush = () => new Promise((resolve) => setImmediate(resolve));
const host = () => ({
  task_definition: [],
  runtime_context: [],
  launcher_settings: [],
});
const scenario = (fixtureHash, symptom) => ({
  fixture_hash: fixtureHash,
  scenario: {
    incident_id: "watchdog-window-flash",
    symptom,
    hosts: { A: host(), B: host() },
  },
});
const run = (fixtureHash, marker) => ({
  status: "succeeded",
  fixture_hash: fixtureHash,
  fixture_version: "1.0",
  provider: marker,
  model: marker,
  run_id: marker,
  events: [{ type: "diagnosis", summary: marker }],
  plan: [{ id: "plan-1", action: marker }],
  tool_trace: [{ status: "ALLOWED", name: marker, host: "A" }],
  evidence: [{ id: "evidence-1", host: "A", field: marker, value: marker }],
  diagnosis: {
    observed: [{ statement: marker, evidence_ids: ["evidence-1"] }],
    inferences: [{ statement: marker, evidence_ids: ["evidence-1"] }],
    root_cause: marker,
    confidence: marker,
    decisive_evidence_ids: ["evidence-1"],
    ruled_out: [{ statement: marker, evidence_ids: ["evidence-1"] }],
  },
  proposal: {
    label: "Simulated",
    title: `proposal ${marker}`,
    expected_outcome: marker,
    changes: [{ field: "logon_type", from: "InteractiveToken", to: "S4U" }],
    prerequisites: [marker],
    limitations: [marker],
    rollback: [{ field: "logon_type", from: "S4U", to: "InteractiveToken" }],
    verification_checks: [{ label: marker, expected: "S4U" }],
  },
  run_hash: `run-hash-${marker}`,
  proposal_hash: `proposal-hash-${marker}`,
  approval: { token: marker, expires_at: 9999999999, expires_at_utc: "2286-11-20T17:46:39Z" },
});
const policy = (marker) => ({ status: "BLOCKED_BY_POLICY", reason: marker });
const decision = () => ({
  status: "succeeded",
  decision: "approved",
  reason: "approved for simulation",
  applied: true,
  simulation: true,
  simulation_label: "SIMULATED - NO REAL HOST CHANGED",
  before: { logon_type: "InteractiveToken", session_id: 1, interactive: true, state: "Ready", last_task_result: 0 },
  after: { logon_type: "S4U", session_id: 0, interactive: false, state: "Ready", last_task_result: 0 },
  verification: {
    success: true,
    checks: [{ label: "Logon type is S4U", expected: "S4U", actual: "S4U", passed: true }],
  },
  decision_token: "report-token",
});

(async () => {
  vm.runInThisContext(fs.readFileSync("static/app.js", "utf8"), { filename: "static/app.js" });
  assert.equal(elements["run-button"].disabled, true);
  assert.equal(pending.length, 1);

  pending[0].resolve(scenario("hash-1", "first scenario"));
  await flush();
  assert.equal(elements["run-button"].disabled, false);

  elements["run-button"].click();
  await flush();
  assert.equal(pending[1].url, "/api/run");
  elements["load-button"].click();
  await flush();
  assert.equal(pending[1].options.signal.aborted, true);
  pending[2].resolve(scenario("hash-2", "reset scenario"));
  await flush();
  pending[1].resolve(run("hash-1", "stale success"));
  await flush();
  assert.equal(elements.status.textContent, "Scenario loaded");
  assert.equal(elements["fixture-hash"].textContent, "hash-2");
  assert.equal(elements["root-cause"].textContent, "Awaiting investigation.");
  assert.equal(elements.provenance.children.length, 0);

  elements["run-button"].click();
  await flush();
  elements["load-button"].click();
  await flush();
  pending[4].resolve(scenario("hash-3", "failure reset scenario"));
  await flush();
  pending[3].reject(new Error("stale provider failure"));
  await flush();
  assert.equal(elements.status.textContent, "Scenario loaded");
  assert.equal(elements["fixture-hash"].textContent, "hash-3");
  assert.equal(elements["root-cause"].textContent, "Awaiting investigation.");

  elements["run-button"].click();
  await flush();
  pending[5].resolve(run("wrong-hash", "mixed provenance"));
  await flush();
  assert.match(elements.status.textContent, /^Failed: Run evidence does not match/);
  assert.equal(elements["root-cause"].textContent, "Awaiting investigation.");
  assert.equal(elements["run-button"].disabled, false);

  const marker = "<img src=x onerror=alert(1)>";
  elements["run-button"].click();
  await flush();
  pending[6].resolve(run("hash-3", marker));
  await flush();
  assert.equal(elements.status.textContent, "Investigation complete - approval required");
  assert.equal(elements["root-cause"].textContent, marker);
  assert.equal(elements.observed.children[0].textContent, `${marker} [evidence-1]`);
  assert.equal(elements.provenance.children[1].textContent, marker);

  elements["run-button"].click();
  await flush();
  elements["policy-button"].click();
  await flush();
  assert.match(elements.status.textContent, /^Running live Qwen investigation/);
  assert.equal(elements.status.dataset.kind, "running");
  pending[8].resolve(policy("resolved before run"));
  await flush();
  assert.match(elements.status.textContent, /^Running live Qwen investigation/);
  assert.equal(elements.status.dataset.kind, "running");
  assert.equal(elements["policy-result"].textContent, "BLOCKED_BY_POLICY: resolved before run");
  pending[7].resolve(run("hash-3", "policy-before"));
  await flush();
  assert.equal(elements.status.textContent, "Investigation complete - approval required");

  elements["policy-button"].click();
  await flush();
  elements["run-button"].click();
  await flush();
  pending[10].resolve(run("hash-3", "policy-after"));
  await flush();
  assert.equal(elements.status.textContent, "Investigation complete - approval required");
  pending[9].resolve(policy("resolved after run"));
  await flush();
  assert.equal(elements.status.textContent, "Investigation complete - approval required");
  assert.equal(elements["policy-result"].textContent, "BLOCKED_BY_POLICY: resolved after run");

  elements["policy-button"].click();
  elements["policy-button"].click();
  await flush();
  pending[12].resolve(policy("new policy result"));
  await flush();
  pending[11].resolve(policy("stale policy result"));
  await flush();
  assert.equal(elements.status.textContent, "Investigation complete - approval required");
  assert.equal(elements["policy-result"].textContent, "BLOCKED_BY_POLICY: new policy result");

  elements["approve-button"].click();
  await flush();
  assert.equal(pending[13].url, "/api/approve");
  assert.equal(JSON.parse(pending[13].options.body).run.run_id, "policy-after");
  pending[13].resolve(decision());
  await flush();
  assert.equal(elements.status.textContent, "Simulated change verified");
  assert.equal(elements["decision-section"].hidden, false);
  assert.equal(elements["report-button"].disabled, false);

  elements["report-button"].click();
  await flush();
  assert.equal(pending[14].url, "/api/report");
  pending[14].resolve("report");
  await flush();
  assert.equal(elements.status.textContent, "Audit report downloaded");
})().catch((error) => {
  console.error(error.stack || error);
  process.exitCode = 1;
});
"""
        completed = subprocess.run(
            ["node", "-"],
            input=smoke,
            text=True,
            capture_output=True,
            cwd=Path(__file__).resolve().parent,
            timeout=10,
            check=False,
        )
        self.assertEqual(0, completed.returncode, completed.stderr or completed.stdout)


class QwenLiveSmoke(unittest.TestCase):
    @unittest.skipUnless(
        os.getenv("DASHSCOPE_API_KEY") and os.getenv("DASHSCOPE_BASE_URL"),
        "requires DASHSCOPE_API_KEY and DASHSCOPE_BASE_URL",
    )
    def test_live_qwen_smoke(self) -> None:
        result = app.run_investigation()
        self.assertEqual("succeeded", result["status"])
        self.assertEqual(3, result["model_response_count"])
        self.assertEqual(4, result["processed_tool_calls"])
        self.assertEqual("plan", result["events"][0]["type"])
        self.assertEqual(list(app.EXPECTED_TOOL_SEQUENCE), [(call["name"], call["host"]) for call in result["tool_trace"]])
        evidence_ids = {item["id"] for item in result["evidence"]}
        diagnosis = result["diagnosis"]
        cited_ids = set(diagnosis["decisive_evidence_ids"])
        for field in ("observed", "inferences"):
            for item in diagnosis[field]:
                cited_ids.update(item["evidence_ids"])
        for item in diagnosis["ruled_out"]:
            cited_ids.update(item["evidence_ids"])
        self.assertTrue(cited_ids)
        self.assertLessEqual(cited_ids, evidence_ids)
        self.assertEqual("Simulated", result["proposal"]["label"])
        self.assertEqual(app.value_hash(result["proposal"]), result["proposal_hash"])
        run_core, proposal, fixture = app._validate_run_envelope(
            result,
            enforce_approval_expiry=True,
        )
        self.assertEqual(result["run_id"], run_core["run_id"])
        self.assertEqual(app.build_simulated_proposal(), proposal)
        self.assertEqual(result["fixture_hash"], app.fixture_hash(fixture))


if __name__ == "__main__":
    unittest.main()
