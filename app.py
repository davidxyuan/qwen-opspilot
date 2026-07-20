"""Qwen OpsPilot: a dependency-free, fixture-backed incident diagnosis demo."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import os
import re
import secrets
import socket
import threading
import time
from copy import deepcopy
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


ROOT = Path(__file__).resolve().parent
FIXTURE_PATH = ROOT / "fixtures" / "watchdog.json"
STATIC_FILES = {
    "/": (ROOT / "static" / "index.html", "text/html; charset=utf-8"),
    "/static/app.js": (ROOT / "static" / "app.js", "text/javascript; charset=utf-8"),
    "/static/styles.css": (ROOT / "static" / "styles.css", "text/css; charset=utf-8"),
}
MAX_REQUEST_BYTES = 32 * 1024
MAX_MODEL_RESPONSES = 3
MAX_TOOL_CALLS = 4
QWEN_TIMEOUT_SECONDS = 45
MAX_RETRY_AFTER_SECONDS = 2
APPROVAL_TTL_SECONDS = 15 * 60
REPORT_TTL_SECONDS = 60 * 60
PROVIDER = "Alibaba Cloud Model Studio"
DEFAULT_MODEL = "qwen3.7-plus"
QWEN_CLOUD_HOST = "dashscope-intl.aliyuncs.com"
SINGAPORE_HOST_SUFFIX = ".ap-southeast-1.maas.aliyuncs.com"
RUN_LOCK = threading.Lock()
SIMULATION_LABEL = "SIMULATED - NO REAL HOST CHANGED"
RUN_CORE_KEYS = {
    "status",
    "provider",
    "model",
    "run_id",
    "fixture_version",
    "fixture_hash",
    "plan",
    "events",
    "tool_trace",
    "allowed_calls",
    "blocked_calls",
    "evidence",
    "diagnosis",
    "model_response_count",
    "processed_tool_calls",
}
RUN_ENVELOPE_KEYS = RUN_CORE_KEYS | {"proposal", "proposal_hash", "run_hash", "approval"}
DECISION_CORE_KEYS = {
    "status",
    "decision",
    "reason",
    "applied",
    "simulation",
    "simulation_label",
    "run_id",
    "fixture_hash",
    "proposal_hash",
    "before",
    "after",
    "verification",
}
EXPECTED_TOOL_SEQUENCE = (
    ("compare_task_definitions", "A"),
    ("compare_task_definitions", "B"),
    ("compare_runtime_context", "A"),
    ("compare_runtime_context", "B"),
)
FALSE_REMEDIATION_CLAIM_PATTERNS = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"\b(?:problem|issue|incident)\b[^.!?\n]{0,80}\b(?:fixed|resolved|remediated)\b",
        r"\b(?:remediation|fix|change)\b[^.!?\n]{0,80}\b(?:succeeded|successful|fixed|resolved|remediated)\b",
        r"\bhost\s+[ab]\b[^.!?\n]{0,80}\bno\s+longer\b[^.!?\n]{0,80}\b(?:flash(?:es|ed|ing)?|visible)\b",
    )
)


def _load_approval_secret() -> bytes:
    """Load a stable deployment secret or create an ephemeral local-only key."""
    configured = os.getenv("OPSPILOT_HMAC_SECRET", "")
    if not configured:
        return secrets.token_bytes(32)
    if len(configured) < 32 or len(configured) > 1024:
        raise RuntimeError("OPSPILOT_HMAC_SECRET must contain 32 to 1024 characters.")
    return hashlib.sha256(configured.encode("utf-8")).digest()


APPROVAL_SECRET = _load_approval_secret()


def server_binding() -> tuple[str, int]:
    """Return a validated local or Function Compute HTTP listener."""
    host = os.getenv("OPSPILOT_BIND_HOST", "127.0.0.1")
    if host not in {"127.0.0.1", "0.0.0.0"}:
        raise RuntimeError("OPSPILOT_BIND_HOST must be 127.0.0.1 or 0.0.0.0.")
    raw_port = os.getenv("FC_CUSTOM_LISTEN_PORT") or os.getenv("PORT", "9000")
    try:
        port = int(raw_port)
    except (TypeError, ValueError) as exc:
        raise RuntimeError("The configured listener port must be an integer.") from exc
    if not 1 <= port <= 65535:
        raise RuntimeError("The configured listener port must be between 1 and 65535.")
    return host, port


def send_security_headers(handler: BaseHTTPRequestHandler) -> None:
    handler.send_header("X-Content-Type-Options", "nosniff")
    handler.send_header("X-Frame-Options", "DENY")
    handler.send_header("Referrer-Policy", "no-referrer")
    handler.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    handler.send_header(
        "Content-Security-Policy",
        "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; "
        "form-action 'none'; object-src 'none'",
    )


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, request: Request, *args: Any, **kwargs: Any) -> None:
        return None


QWEN_OPENER = build_opener(_NoRedirectHandler())


def load_fixture() -> dict[str, Any]:
    """Return a fresh fixture value for each request or tool invocation."""
    with FIXTURE_PATH.open("r", encoding="utf-8") as handle:
        return deepcopy(json.load(handle))


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"Invalid JSON constant: {value}")


def canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def fixture_hash(fixture: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(fixture).encode("utf-8")).hexdigest()


def value_hash(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def json_response(handler: BaseHTTPRequestHandler, status: int, payload: dict[str, Any]) -> None:
    try:
        body = canonical_json(payload).encode("utf-8")
    except (TypeError, ValueError, RecursionError):
        status = 500
        body = b'{"error":{"code":"SERVER_ERROR","message":"Response serialization failed."}}'
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Cache-Control", "no-store")
    send_security_headers(handler)
    handler.end_headers()
    handler.wfile.write(body)


def markdown_response(handler: BaseHTTPRequestHandler, body: str) -> None:
    encoded = body.encode("utf-8")
    handler.send_response(200)
    handler.send_header("Content-Type", "text/markdown; charset=utf-8")
    handler.send_header("Content-Disposition", 'attachment; filename="qwen-opspilot-report.md"')
    handler.send_header("Content-Length", str(len(encoded)))
    handler.send_header("Cache-Control", "no-store")
    send_security_headers(handler)
    handler.end_headers()
    handler.wfile.write(encoded)


class RequestError(ValueError):
    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.code = code


class QwenError(RuntimeError):
    """A safe, non-secret Qwen integration failure."""

    def __init__(self, code: str, message: str, status: int = 502) -> None:
        super().__init__(message)
        self.code = code
        self.status = status


class DiagnosisValidationError(ValueError):
    pass


class IntegrityValidationError(ValueError):
    """A fixed, non-secret integrity-boundary failure."""

    def __init__(self, code: str, message: str, status: int = 403) -> None:
        super().__init__(message)
        self.code = code
        self.status = status


def build_simulated_proposal() -> dict[str, Any]:
    """Return the only remediation shape this MVP is allowed to simulate."""
    return {
        "id": "host-a-watchdog-s4u-v1",
        "label": "Simulated",
        "title": "Simulated: move the Host A watchdog from InteractiveToken to S4U",
        "target": "Host A fixture clone only",
        "expected_outcome": (
            "The cloned watchdog runs outside the interactive desktop session, so the simulated "
            "PowerShell window cannot interrupt the signed-in user's desktop."
        ),
        "changes": [
            {
                "group": "task_definition",
                "field": "logon_type",
                "from": "InteractiveToken",
                "to": "S4U",
            },
            {"group": "runtime_context", "field": "session_id", "from": 1, "to": 0},
            {"group": "runtime_context", "field": "interactive", "from": True, "to": False},
        ],
        "prerequisites": [
            "Use a service identity that has permission to run the watchdog task.",
            "Confirm the watchdog does not require an interactive desktop or mapped user drives.",
            "Store any required credentials outside the task definition and this demo.",
        ],
        "limitations": [
            "S4U has no interactive desktop and cannot display prompts or UI.",
            "Network access depends on the selected account and environment; mapped drives are unavailable.",
            "This demo changes synthetic request data only and does not validate a real Windows host.",
        ],
        "rollback": [
            {
                "group": "task_definition",
                "field": "logon_type",
                "from": "S4U",
                "to": "InteractiveToken",
            },
            {"group": "runtime_context", "field": "session_id", "from": 0, "to": 1},
            {"group": "runtime_context", "field": "interactive", "from": False, "to": True},
        ],
        "verification_checks": [
            {"id": "verify-s4u", "label": "Logon type is S4U", "field": "logon_type", "expected": "S4U"},
            {"id": "verify-session-0", "label": "Runtime is in Session 0", "field": "session_id", "expected": 0},
            {
                "id": "verify-non-interactive",
                "label": "Runtime is non-interactive",
                "field": "interactive",
                "expected": False,
            },
            {"id": "verify-ready", "label": "Task state remains Ready", "field": "state", "expected": "Ready"},
            {
                "id": "verify-last-result",
                "label": "LastTaskResult remains 0",
                "field": "last_task_result",
                "expected": 0,
            },
        ],
    }


def _utc_text(epoch: int) -> str:
    return datetime.fromtimestamp(epoch, timezone.utc).isoformat().replace("+00:00", "Z")


def _base64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _base64url_decode(value: str) -> bytes:
    if not value or len(value) > 8192 or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise IntegrityValidationError("INVALID_TOKEN", "Approval token is invalid.")
    try:
        padding = "=" * (-len(value) % 4)
        return base64.b64decode(value + padding, altchars=b"-_", validate=True)
    except (ValueError, TypeError):
        raise IntegrityValidationError("INVALID_TOKEN", "Approval token is invalid.") from None


def _sign_payload(payload: dict[str, Any]) -> str:
    encoded = _base64url_encode(canonical_json(payload).encode("utf-8"))
    signature = hmac.new(APPROVAL_SECRET, encoded.encode("ascii"), hashlib.sha256).digest()
    return f"{encoded}.{_base64url_encode(signature)}"


def _verify_signed_payload(token: Any) -> dict[str, Any]:
    if not isinstance(token, str) or len(token) > 16384 or token.count(".") != 1:
        raise IntegrityValidationError("INVALID_TOKEN", "Approval token is invalid.")
    encoded, supplied_signature = token.split(".", 1)
    expected_signature = hmac.new(
        APPROVAL_SECRET,
        encoded.encode("ascii", errors="ignore"),
        hashlib.sha256,
    ).digest()
    supplied = _base64url_decode(supplied_signature)
    if not hmac.compare_digest(expected_signature, supplied):
        raise IntegrityValidationError("INVALID_TOKEN", "Approval token is invalid.")
    try:
        payload = json.loads(_base64url_decode(encoded), parse_constant=_reject_json_constant)
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise IntegrityValidationError("INVALID_TOKEN", "Approval token is invalid.") from None
    if not isinstance(payload, dict):
        raise IntegrityValidationError("INVALID_TOKEN", "Approval token is invalid.")
    return payload


def create_approval_capability(
    run_core: dict[str, Any],
    fixture: dict[str, Any],
    proposal: dict[str, Any],
) -> dict[str, Any]:
    expires_at = int(time.time()) + APPROVAL_TTL_SECONDS
    run_digest = value_hash(run_core)
    proposal_digest = value_hash(proposal)
    token_payload = {
        "kind": "approval",
        "run_id": run_core["run_id"],
        "fixture_version": fixture["fixture_version"],
        "fixture_hash": run_core["fixture_hash"],
        "run_hash": run_digest,
        "proposal_hash": proposal_digest,
        "expires_at": expires_at,
    }
    return {
        "run_hash": run_digest,
        "proposal_hash": proposal_digest,
        "approval": {
            "token": _sign_payload(token_payload),
            "expires_at": expires_at,
            "expires_at_utc": _utc_text(expires_at),
        },
    }


def _validate_run_envelope(
    run: Any,
    *,
    enforce_approval_expiry: bool,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    if not isinstance(run, dict) or set(run) != RUN_ENVELOPE_KEYS:
        raise IntegrityValidationError("INVALID_RUN", "Signed run envelope is invalid.")
    run_core = {key: deepcopy(run[key]) for key in RUN_CORE_KEYS}
    if (
        run_core.get("status") != "succeeded"
        or run_core.get("provider") != PROVIDER
        or not isinstance(run_core.get("run_id"), str)
        or not run_core["run_id"]
        or not isinstance(run_core.get("fixture_version"), str)
        or not isinstance(run_core.get("fixture_hash"), str)
    ):
        raise IntegrityValidationError("INVALID_RUN", "Signed run envelope is invalid.")
    proposal = run.get("proposal")
    expected_proposal = build_simulated_proposal()
    if proposal != expected_proposal or run.get("proposal_hash") != value_hash(expected_proposal):
        raise IntegrityValidationError("PROPOSAL_TAMPERED", "Simulated proposal failed integrity validation.")
    computed_run_hash = value_hash(run_core)
    if run.get("run_hash") != computed_run_hash:
        raise IntegrityValidationError("RUN_TAMPERED", "Investigation run failed integrity validation.")
    approval = run.get("approval")
    if not isinstance(approval, dict) or set(approval) != {"token", "expires_at", "expires_at_utc"}:
        raise IntegrityValidationError("INVALID_TOKEN", "Approval token is invalid.")
    if type(approval.get("expires_at")) is not int or approval.get("expires_at_utc") != _utc_text(approval["expires_at"]):
        raise IntegrityValidationError("INVALID_TOKEN", "Approval token is invalid.")
    token_payload = _verify_signed_payload(approval.get("token"))
    expected_token_payload = {
        "kind": "approval",
        "run_id": run_core["run_id"],
        "fixture_version": run_core["fixture_version"],
        "fixture_hash": run_core["fixture_hash"],
        "run_hash": computed_run_hash,
        "proposal_hash": run["proposal_hash"],
        "expires_at": approval["expires_at"],
    }
    if token_payload != expected_token_payload:
        raise IntegrityValidationError("TOKEN_BINDING_FAILED", "Approval token does not match this run.")
    if enforce_approval_expiry and approval["expires_at"] < int(time.time()):
        raise IntegrityValidationError("TOKEN_EXPIRED", "Approval token has expired.")
    fixture = load_fixture()
    if (
        fixture.get("fixture_version") != run_core["fixture_version"]
        or fixture_hash(fixture) != run_core["fixture_hash"]
    ):
        raise IntegrityValidationError("FIXTURE_CHANGED", "Fixture version or hash no longer matches this run.")
    return run_core, deepcopy(proposal), fixture


def _fixture_field(fixture: dict[str, Any], group: str, field: str) -> Any:
    records = fixture["hosts"]["A"][group]
    matches = [record for record in records if record.get("field") == field]
    if len(matches) != 1:
        raise IntegrityValidationError("FIXTURE_INVALID", "Fixture does not contain the required field.", 500)
    return matches[0].get("value")


def _set_fixture_field(
    fixture: dict[str, Any],
    group: str,
    field: str,
    before: Any,
    after: Any,
) -> None:
    records = fixture["hosts"]["A"][group]
    matches = [record for record in records if record.get("field") == field]
    if len(matches) != 1 or matches[0].get("value") != before:
        raise IntegrityValidationError("FIXTURE_INVALID", "Fixture does not match the fixed proposal.", 500)
    matches[0]["value"] = after


def remediation_snapshot(fixture: dict[str, Any]) -> dict[str, Any]:
    return {
        "logon_type": _fixture_field(fixture, "task_definition", "logon_type"),
        "session_id": _fixture_field(fixture, "runtime_context", "session_id"),
        "interactive": _fixture_field(fixture, "runtime_context", "interactive"),
        "state": _fixture_field(fixture, "task_definition", "state"),
        "last_task_result": _fixture_field(fixture, "task_definition", "last_task_result"),
    }


def verify_simulated_remediation(fixture: dict[str, Any]) -> dict[str, Any]:
    actual = remediation_snapshot(fixture)
    checks = []
    for definition in build_simulated_proposal()["verification_checks"]:
        observed = actual[definition["field"]]
        checks.append(
            {
                "id": definition["id"],
                "label": definition["label"],
                "expected": definition["expected"],
                "actual": observed,
                "passed": type(observed) is type(definition["expected"])
                and observed == definition["expected"],
            }
        )
    return {"success": all(check["passed"] for check in checks), "checks": checks}


def apply_simulated_remediation(
    fixture: dict[str, Any],
    proposal: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    if proposal != build_simulated_proposal():
        raise IntegrityValidationError("PROPOSAL_TAMPERED", "Simulated proposal failed integrity validation.")
    clone = deepcopy(fixture)
    before = remediation_snapshot(clone)
    for change in proposal["changes"]:
        _set_fixture_field(
            clone,
            change["group"],
            change["field"],
            change["from"],
            change["to"],
        )
    after = remediation_snapshot(clone)
    verification = verify_simulated_remediation(clone)
    return clone, before, after, verification


def _decision_core(
    run_core: dict[str, Any],
    proposal: dict[str, Any],
    fixture: dict[str, Any],
    action: str,
) -> dict[str, Any]:
    if action == "approved":
        _, before, after, verification = apply_simulated_remediation(fixture, proposal)
        applied = verification["success"]
        reason = "User approved the integrity-checked simulated change."
    elif action == "rejected":
        before = remediation_snapshot(fixture)
        after = deepcopy(before)
        verification = verify_simulated_remediation(fixture)
        applied = False
        reason = "User rejected the simulated change; state remained unchanged."
    else:
        raise IntegrityValidationError("INVALID_DECISION", "Decision action is invalid.", 400)
    return {
        "status": "succeeded",
        "decision": action,
        "reason": reason,
        "applied": applied,
        "simulation": True,
        "simulation_label": SIMULATION_LABEL,
        "run_id": run_core["run_id"],
        "fixture_hash": run_core["fixture_hash"],
        "proposal_hash": value_hash(proposal),
        "before": before,
        "after": after,
        "verification": verification,
    }


def _issue_decision(
    run: dict[str, Any],
    run_core: dict[str, Any],
    proposal: dict[str, Any],
    fixture: dict[str, Any],
    action: str,
) -> dict[str, Any]:
    core = _decision_core(run_core, proposal, fixture, action)
    report_expires_at = run["approval"]["expires_at"] + REPORT_TTL_SECONDS
    token_payload = {
        "kind": "decision",
        "run_hash": run["run_hash"],
        "proposal_hash": run["proposal_hash"],
        "decision_hash": value_hash(core),
        "expires_at": report_expires_at,
    }
    return {
        **core,
        "decision_token": _sign_payload(token_payload),
        "report_expires_at": report_expires_at,
        "report_expires_at_utc": _utc_text(report_expires_at),
    }


def _unchanged_failure_decision(action: str, reason: str) -> dict[str, Any]:
    fixture = load_fixture()
    snapshot = remediation_snapshot(fixture)
    return {
        "status": "failed",
        "decision": action,
        "reason": reason,
        "applied": False,
        "simulation": True,
        "simulation_label": SIMULATION_LABEL,
        "before": snapshot,
        "after": deepcopy(snapshot),
        "verification": verify_simulated_remediation(fixture),
    }


def _validate_decision_envelope(
    run: dict[str, Any],
    run_core: dict[str, Any],
    proposal: dict[str, Any],
    fixture: dict[str, Any],
    decision: Any,
) -> dict[str, Any]:
    envelope_keys = DECISION_CORE_KEYS | {
        "decision_token",
        "report_expires_at",
        "report_expires_at_utc",
    }
    if not isinstance(decision, dict) or set(decision) != envelope_keys:
        raise IntegrityValidationError("INVALID_DECISION", "Decision envelope is invalid.")
    action = decision.get("decision")
    if action not in {"approved", "rejected"}:
        raise IntegrityValidationError("INVALID_DECISION", "Decision envelope is invalid.")
    expected_core = _decision_core(run_core, proposal, fixture, action)
    supplied_core = {key: deepcopy(decision[key]) for key in DECISION_CORE_KEYS}
    if supplied_core != expected_core:
        raise IntegrityValidationError("DECISION_TAMPERED", "Decision result failed integrity validation.")
    expiry = decision.get("report_expires_at")
    if type(expiry) is not int or decision.get("report_expires_at_utc") != _utc_text(expiry):
        raise IntegrityValidationError("INVALID_DECISION", "Decision envelope is invalid.")
    token_payload = _verify_signed_payload(decision.get("decision_token"))
    expected_payload = {
        "kind": "decision",
        "run_hash": run["run_hash"],
        "proposal_hash": run["proposal_hash"],
        "decision_hash": value_hash(expected_core),
        "expires_at": expiry,
    }
    if token_payload != expected_payload:
        raise IntegrityValidationError("DECISION_TAMPERED", "Decision result failed integrity validation.")
    if expiry < int(time.time()):
        raise IntegrityValidationError("REPORT_EXPIRED", "Report capability has expired.")
    return expected_core


def _markdown_json(value: Any) -> list[str]:
    rendered = json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, indent=2)
    return [f"    {line}" for line in rendered.splitlines()]


def build_markdown_report(run: dict[str, Any], decision: dict[str, Any]) -> str:
    fixture = load_fixture()
    sections: list[tuple[str, Any]] = [
        ("Symptom", fixture["symptom"]),
        (
            "Qwen provenance",
            {"provider": run["provider"], "model": run["model"], "run_id": run["run_id"]},
        ),
        ("Investigation plan", run["plan"]),
        ("Tool trace", run["tool_trace"]),
        ("Evidence", run["evidence"]),
        ("Diagnosis", run["diagnosis"]),
        ("Simulated proposal", run["proposal"]),
        (
            "Integrity hashes and expiry",
            {
                "fixture_version": run["fixture_version"],
                "fixture_hash": run["fixture_hash"],
                "run_hash": run["run_hash"],
                "proposal_hash": run["proposal_hash"],
                "approval_expires_at_utc": run["approval"]["expires_at_utc"],
            },
        ),
        (
            "Approval decision",
            {
                "decision": decision["decision"],
                "reason": decision["reason"],
                "applied": decision["applied"],
                "simulation": decision["simulation"],
                "simulation_label": decision["simulation_label"],
            },
        ),
        ("Before state", decision["before"]),
        ("After state", decision["after"]),
        ("Deterministic verification", decision["verification"]),
        ("Rollback", run["proposal"]["rollback"]),
    ]
    lines = [
        "# Qwen OpsPilot Incident Report",
        "",
        f"> **{SIMULATION_LABEL}**",
        "",
        "This report records a synthetic evaluation. It is not evidence of a real host change.",
    ]
    for heading, value in sections:
        lines.extend(["", f"## {heading}", ""])
        lines.extend(_markdown_json(value))
    lines.extend(["", f"> **{SIMULATION_LABEL}**", ""])
    return "\n".join(lines)


def _qwen_configuration() -> tuple[str, str, str]:
    api_key = os.getenv("DASHSCOPE_API_KEY", "")
    base_url = os.getenv("DASHSCOPE_BASE_URL", "").rstrip("/")
    model = os.getenv("QWEN_MODEL", DEFAULT_MODEL)
    try:
        parsed = urlsplit(base_url)
        hostname = parsed.hostname or ""
        valid_host = hostname == QWEN_CLOUD_HOST or (
            hostname.endswith(SINGAPORE_HOST_SUFFIX)
            and hostname != SINGAPORE_HOST_SUFFIX.lstrip(".")
        )
        valid_base = (
            parsed.scheme == "https"
            and valid_host
            and parsed.path == "/compatible-mode/v1"
            and not parsed.query
            and not parsed.fragment
            and parsed.username is None
            and parsed.password is None
            and parsed.port is None
        )
    except ValueError:
        valid_base = False
    if not api_key or not valid_base:
        raise QwenError(
            "QWEN_NOT_CONFIGURED",
            "Qwen requires an API key and an approved compatible-mode base URL.",
            503,
        )
    return api_key, base_url, model


def _is_temporary_transport(error: BaseException) -> bool:
    reason = error.reason if isinstance(error, URLError) else error
    return isinstance(reason, (TimeoutError, socket.timeout, ConnectionError))


def _retry_after_seconds(error: HTTPError) -> float:
    try:
        return min(MAX_RETRY_AFTER_SECONDS, max(0.0, float(error.headers.get("Retry-After", "0"))))
    except (AttributeError, TypeError, ValueError):
        return 0.0


def qwen_chat(
    messages: list[dict[str, Any]],
    *,
    tools: list[dict[str, Any]] | None = None,
    response_format: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Call the workspace-scoped Qwen Chat Completions endpoint with one retry."""
    api_key, base_url, model = _qwen_configuration()
    payload: dict[str, Any] = {
        "model": model,
        "messages": messages,
        "enable_thinking": False,
        "temperature": 0,
    }
    if tools is not None:
        payload["tools"] = tools
        payload["parallel_tool_calls"] = True
    if response_format is not None:
        payload["response_format"] = response_format
    request = Request(
        f"{base_url}/chat/completions",
        data=canonical_json(payload).encode("utf-8"),
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        method="POST",
    )

    for attempt in range(2):
        try:
            with QWEN_OPENER.open(request, timeout=QWEN_TIMEOUT_SECONDS) as response:
                document = json.load(response, parse_constant=_reject_json_constant)
            choices = document.get("choices") if isinstance(document, dict) else None
            choice = choices[0] if isinstance(choices, list) and choices else None
            message = choice.get("message") if isinstance(choice, dict) else None
            if not isinstance(message, dict):
                raise QwenError("QWEN_PROVIDER_ERROR", "Qwen returned an invalid response.")
            return message
        except HTTPError as error:
            if attempt == 0 and (error.code == 429 or error.code >= 500):
                delay = _retry_after_seconds(error)
                if delay:
                    time.sleep(delay)
                continue
            raise QwenError("QWEN_PROVIDER_ERROR", "Qwen request failed.") from None
        except (URLError, TimeoutError, socket.timeout, ConnectionError) as error:
            if attempt == 0 and _is_temporary_transport(error):
                continue
            raise QwenError("QWEN_PROVIDER_ERROR", "Qwen request failed.") from None
        except (OSError, ValueError, RecursionError):
            raise QwenError("QWEN_PROVIDER_ERROR", "Qwen returned an invalid response.") from None
    raise QwenError("QWEN_PROVIDER_ERROR", "Qwen request failed.")


def _message_json(message: dict[str, Any], label: str) -> dict[str, Any]:
    content = message.get("content")
    if not isinstance(content, str):
        raise QwenError("QWEN_PROVIDER_ERROR", f"Qwen {label} was not JSON text.")
    try:
        value = json.loads(content, parse_constant=_reject_json_constant)
    except (ValueError, RecursionError):
        raise QwenError("QWEN_PROVIDER_ERROR", f"Qwen {label} was invalid JSON.") from None
    if not isinstance(value, dict):
        raise QwenError("QWEN_PROVIDER_ERROR", f"Qwen {label} must be a JSON object.")
    return value


def create_plan(symptom: str) -> list[dict[str, str]]:
    """Ask Qwen for a plan using only the ambiguous symptom."""
    message = qwen_chat(
        [
            {
                "role": "system",
                "content": (
                    "Create a concise read-only Windows incident investigation plan. "
                    "Return JSON only as {\"plan\":[{\"action\":\"...\"}]}. "
                    "Use 3 to 5 steps and do not claim a diagnosis before evidence is collected."
                ),
            },
            {"role": "user", "content": symptom},
        ],
        response_format={"type": "json_object"},
    )
    document = _message_json(message, "plan")
    items = document.get("plan")
    if not isinstance(items, list) or not 3 <= len(items) <= 5:
        raise QwenError("QWEN_PROVIDER_ERROR", "Qwen plan must contain 3 to 5 items.")
    plan: list[dict[str, str]] = []
    for index, item in enumerate(items, 1):
        action = item.get("action") if isinstance(item, dict) else item
        if not isinstance(action, str) or not action.strip() or len(action) > 500:
            raise QwenError("QWEN_PROVIDER_ERROR", "Qwen plan contains an invalid item.")
        plan.append({"id": f"plan-{index}", "action": action.strip()})
    return plan


def _read_fixture_group(host: str, fixture: dict[str, Any], group: str) -> list[dict[str, Any]]:
    return deepcopy(fixture["hosts"][host][group])


def compare_task_definitions(host: str, fixture: dict[str, Any]) -> list[dict[str, Any]]:
    return _read_fixture_group(host, fixture, "task_definition")


def compare_runtime_context(host: str, fixture: dict[str, Any]) -> list[dict[str, Any]]:
    return _read_fixture_group(host, fixture, "runtime_context")


def compare_launcher_settings(host: str, fixture: dict[str, Any]) -> list[dict[str, Any]]:
    return _read_fixture_group(host, fixture, "launcher_settings")


TOOL_HANDLERS = {
    "compare_task_definitions": compare_task_definitions,
    "compare_runtime_context": compare_runtime_context,
    "compare_launcher_settings": compare_launcher_settings,
}

TOOL_SCHEMAS = [
    {
        "type": "function",
        "function": {
            "name": name,
            "description": description,
            "parameters": {
                "type": "object",
                "properties": {"host": {"type": "string", "enum": ["A", "B"]}},
                "required": ["host"],
                "additionalProperties": False,
            },
        },
    }
    for name, description in (
        ("compare_task_definitions", "Read normalized scheduled-task facts for one fixture host."),
        ("compare_runtime_context", "Read normalized runtime and session facts for one fixture host."),
        ("compare_launcher_settings", "Read normalized launcher facts for one fixture host."),
    )
]


def _blocked_tool_call(name: Any, reason: str) -> dict[str, Any]:
    return {"status": "BLOCKED_BY_POLICY", "name": str(name), "host": None, "reason": reason}


def execute_tool_call(
    name: Any,
    arguments: Any,
    fixture: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Validate an untrusted model call before dispatching a literal fixture reader."""
    if not isinstance(name, str) or name not in TOOL_HANDLERS:
        return _blocked_tool_call(name, "Unknown tool name.")
    if isinstance(arguments, str):
        try:
            arguments = json.loads(arguments, parse_constant=_reject_json_constant)
        except (ValueError, RecursionError):
            return _blocked_tool_call(name, "Tool arguments are not valid JSON.")
    if not isinstance(arguments, dict):
        return _blocked_tool_call(name, "Tool arguments must be an object.")
    if set(arguments) != {"host"}:
        return _blocked_tool_call(name, "Exactly one host property is required.")
    host = arguments.get("host")
    if not isinstance(host, str) or host not in {"A", "B"}:
        return _blocked_tool_call(name, "Host must be A or B.")
    source = fixture if fixture is not None else load_fixture()
    evidence = TOOL_HANDLERS[name](host, source)
    return {
        "status": "ALLOWED",
        "name": name,
        "host": host,
        "arguments": {"host": host},
        "evidence": evidence,
    }


def _validate_citations(citations: Any, evidence_ids: set[str], message: str) -> None:
    if (
        not isinstance(citations, list)
        or not citations
        or any(not isinstance(citation, str) for citation in citations)
    ):
        raise DiagnosisValidationError(message)
    if len(citations) != len(set(citations)) or not set(citations) <= evidence_ids:
        raise DiagnosisValidationError(message)


def validate_diagnosis(
    diagnosis: dict[str, Any],
    evidence: list[dict[str, Any]],
) -> dict[str, Any]:
    """Reject unsupported claims before the browser receives model output."""
    if not isinstance(diagnosis, dict):
        raise DiagnosisValidationError("Diagnosis must be an object.")
    if not evidence or any(
        not isinstance(item, dict)
        or not isinstance(item.get("id"), str)
        or not isinstance(item.get("host"), str)
        or not isinstance(item.get("field"), str)
        for item in evidence
    ):
        raise DiagnosisValidationError("Current-run evidence records are invalid.")
    evidence_ids = {item["id"] for item in evidence}
    if len(evidence_ids) != len(evidence):
        raise DiagnosisValidationError("Current-run evidence IDs must be unique.")

    for field in ("inferences", "ruled_out"):
        items = diagnosis.get(field)
        if not isinstance(items, list) or not items:
            raise DiagnosisValidationError("Inferences and ruled-out explanations must be separate non-empty lists.")
        for item in items:
            if not isinstance(item, dict) or set(item) != {"statement", "evidence_ids"}:
                raise DiagnosisValidationError(f"Each {field} item needs a statement and evidence_ids.")
            statement = item["statement"]
            citations = item["evidence_ids"]
            if not isinstance(statement, str) or not statement.strip():
                raise DiagnosisValidationError("Diagnosis statements cannot be empty.")
            _validate_citations(citations, evidence_ids, "Diagnosis cites unknown or invalid evidence.")

    root_cause = diagnosis.get("root_cause")
    confidence = diagnosis.get("confidence")
    decisive = diagnosis.get("decisive_evidence_ids")
    ruled_out = diagnosis.get("ruled_out")
    if diagnosis.get("remediation_status") != "not_performed":
        raise DiagnosisValidationError("Phase 1 did not perform remediation.")
    valid_confidence = (
        isinstance(confidence, str) and bool(confidence.strip())
    ) or (
        type(confidence) in (int, float) and math.isfinite(confidence)
    )
    if not isinstance(root_cause, str) or not root_cause.strip() or not valid_confidence:
        raise DiagnosisValidationError("Root cause and confidence are required.")
    _validate_citations(decisive, evidence_ids, "Decisive evidence must cite current-run evidence.")

    root_text = root_cause.lower()
    inference_text = " ".join(item["statement"] for item in diagnosis["inferences"]).lower()
    if "interactive" not in f"{root_text} {inference_text}" or not any(
        term in f"{root_text} {inference_text}" for term in ("logon", "session", "interactivetoken")
    ):
        raise DiagnosisValidationError("Diagnosis must identify interactive logon or session behavior.")
    if "task-a-logon-type" not in decisive or not {
        "runtime-a-session-id",
        "runtime-a-interactive",
    }.intersection(decisive):
        raise DiagnosisValidationError("Interactive task and runtime evidence must be decisive.")
    ruled_out_text = " ".join(item["statement"] for item in ruled_out).lower()
    if "hidden" not in ruled_out_text or not any(
        phrase in ruled_out_text
        for phrase in ("alone", "insufficient", "not sufficient", "shared", "does not explain")
    ):
        raise DiagnosisValidationError("Hidden-window settings must be ruled out as sufficient.")
    hidden_record_ids = {
        item["id"]
        for item in evidence
        if item["field"] in {"arguments", "hidden", "window_style"}
    }
    hidden_citations = {
        cite
        for item in ruled_out
        for cite in item["evidence_ids"]
        if cite in hidden_record_ids
    }
    hidden_hosts = {item["host"] for item in evidence if item["id"] in hidden_citations}
    if hidden_hosts != {"A", "B"}:
        raise DiagnosisValidationError("Hidden-window comparison must cite both hosts.")
    rendered_statements = " ".join(
        [root_cause]
        + [item["statement"] for item in diagnosis["inferences"]]
        + [item["statement"] for item in diagnosis["ruled_out"]]
    )
    if any(pattern.search(rendered_statements) for pattern in FALSE_REMEDIATION_CLAIM_PATTERNS):
        raise DiagnosisValidationError("Phase 1 cannot claim remediation success.")
    validated = deepcopy(diagnosis)
    validated["observed"] = [
        {
            "statement": f"Host {item['host']} {item['field'].replace('_', ' ')}: {canonical_json(item.get('value'))}.",
            "evidence_ids": [item["id"]],
        }
        for item in evidence
    ]
    return validated


def collect_diagnosis(
    symptom: str,
    plan: list[dict[str, str]],
    fixture: dict[str, Any],
) -> dict[str, Any]:
    """Collect the exact four-host comparison calls, then one cited diagnosis."""
    messages: list[dict[str, Any]] = [
        {
            "role": "system",
            "content": (
                "You are a read-only Windows incident investigator. In your next single response, emit exactly "
                "four parallel tool calls simultaneously; do not wait for any tool result. The calls, in this "
                "exact order, are: "
                "compare_task_definitions for A, compare_task_definitions for B, "
                "compare_runtime_context for A, compare_runtime_context for B. "
                "Do not call compare_launcher_settings in this fixed run and do not diagnose before tools return."
            ),
        },
        {
            "role": "user",
            "content": canonical_json({"symptom": symptom, "plan": plan}),
        },
    ]
    tool_message = qwen_chat(messages, tools=TOOL_SCHEMAS)
    raw_calls = tool_message.get("tool_calls")
    if not isinstance(raw_calls, list) or not raw_calls:
        raise QwenError("QWEN_PROVIDER_ERROR", "Qwen did not request evidence tools.")
    if len(raw_calls) > MAX_TOOL_CALLS:
        raise QwenError("TOOL_LIMIT_EXCEEDED", "Qwen exceeded the four-call evidence limit.")
    if len(raw_calls) != len(EXPECTED_TOOL_SEQUENCE):
        raise QwenError("TOOL_SEQUENCE_INVALID", "Qwen did not request the required evidence sequence.")

    assistant_tool_calls: list[dict[str, Any]] = []
    tool_messages: list[dict[str, Any]] = []
    trace: list[dict[str, Any]] = []
    evidence: list[dict[str, Any]] = []
    received_sequence: list[tuple[str, str | None]] = []
    validated_calls: list[tuple[dict[str, Any], dict[str, Any], str]] = []
    seen_call_ids: set[str] = set()
    for raw_call in raw_calls:
        if not isinstance(raw_call, dict) or raw_call.get("type") != "function":
            raise QwenError("QWEN_PROVIDER_ERROR", "Qwen returned an invalid tool-call envelope.")
        function = raw_call.get("function")
        call_id = raw_call.get("id")
        if not isinstance(function, dict) or not isinstance(call_id, str) or not call_id:
            raise QwenError("QWEN_PROVIDER_ERROR", "Qwen returned an invalid tool-call envelope.")
        if call_id in seen_call_ids:
            raise QwenError("QWEN_PROVIDER_ERROR", "Qwen returned duplicate tool-call IDs.")
        seen_call_ids.add(call_id)
        validated_calls.append((raw_call, function, call_id))

    for index, (raw_call, function, call_id) in enumerate(validated_calls, 1):
        name = function.get("name")
        arguments = function.get("arguments")
        result = execute_tool_call(name, arguments, fixture)
        if result["status"] != "ALLOWED":
            raise QwenError("QWEN_PROVIDER_ERROR", "Qwen returned an invalid tool call.")
        result["call_id"] = call_id
        result["sequence"] = index
        trace.append(result)
        received_sequence.append((result["name"], result.get("host")))
        if result["status"] == "ALLOWED":
            for record in result["evidence"]:
                normalized = deepcopy(record)
                normalized["host"] = result["host"]
                normalized["tool"] = result["name"]
                evidence.append(normalized)
        assistant_tool_calls.append(raw_call)
        tool_messages.append(
            {
                "role": "tool",
                "tool_call_id": call_id,
                "name": str(name),
                "content": canonical_json(result),
            }
        )
    if tuple(received_sequence) != EXPECTED_TOOL_SEQUENCE:
        raise QwenError("TOOL_SEQUENCE_INVALID", "Qwen did not request the required evidence sequence.")

    messages.append(
        {
            "role": "assistant",
            "content": tool_message.get("content") or "",
            "tool_calls": assistant_tool_calls,
        }
    )
    messages.extend(tool_messages)
    messages.append(
        {
            "role": "user",
            "content": (
                "Return the final diagnosis as JSON with observed and inferences arrays. Each item must contain "
                "statement and evidence_ids. Also include root_cause, confidence, decisive_evidence_ids, exact "
                'remediation_status "not_performed", and ruled_out, where each ruled_out item also contains '
                "statement and evidence_ids. The application "
                "constructs observed facts from tool records. Identify interactive logon/session behavior and "
                "include a ruled_out item stating that shared hidden-window settings alone are insufficient, "
                "citing hidden/window-style evidence from both hosts. Do not "
                "claim remediation occurred."
            ),
        }
    )
    diagnosis_message = qwen_chat(messages, response_format={"type": "json_object"})
    diagnosis = validate_diagnosis(_message_json(diagnosis_message, "diagnosis"), evidence)
    return {
        "tool_trace": trace,
        "evidence": evidence,
        "diagnosis": diagnosis,
        "model_responses": 2,
        "processed_tool_calls": len(trace),
    }


def run_investigation() -> dict[str, Any]:
    """Execute one bounded plan -> evidence -> diagnosis run."""
    _, _, model = _qwen_configuration()
    fixture = load_fixture()
    run_id = secrets.token_hex(12)
    plan = create_plan(fixture["symptom"])
    collected = collect_diagnosis(fixture["symptom"], plan, fixture)
    if 1 + collected["model_responses"] > MAX_MODEL_RESPONSES:
        raise QwenError("MODEL_LIMIT_EXCEEDED", "Qwen exceeded the three-response limit.")

    events: list[dict[str, Any]] = [
        {"sequence": 1, "type": "plan", "summary": f"Qwen returned {len(plan)} read-only steps."}
    ]
    for call in collected["tool_trace"]:
        events.append(
            {
                "sequence": len(events) + 1,
                "type": "tool",
                "summary": f"{call['name']} read Host {call.get('host') or 'blocked'} evidence.",
                "status": call["status"],
            }
        )
    events.append(
        {"sequence": len(events) + 1, "type": "diagnosis", "summary": "Qwen diagnosis passed citation policy."}
    )
    trace = collected["tool_trace"]
    run_core = {
        "status": "succeeded",
        "provider": PROVIDER,
        "model": model,
        "run_id": run_id,
        "fixture_version": fixture["fixture_version"],
        "fixture_hash": fixture_hash(fixture),
        "plan": plan,
        "events": events,
        "tool_trace": trace,
        "allowed_calls": [call for call in trace if call["status"] == "ALLOWED"],
        "blocked_calls": [call for call in trace if call["status"] == "BLOCKED_BY_POLICY"],
        "evidence": collected["evidence"],
        "diagnosis": collected["diagnosis"],
        "model_response_count": 1 + collected["model_responses"],
        "processed_tool_calls": collected["processed_tool_calls"],
    }
    proposal = build_simulated_proposal()
    capability = create_approval_capability(run_core, fixture, proposal)
    return {
        **run_core,
        "proposal": proposal,
        "proposal_hash": capability["proposal_hash"],
        "run_hash": capability["run_hash"],
        "approval": capability["approval"],
    }


class OpsPilotHandler(BaseHTTPRequestHandler):
    server_version = "OpsPilot/1.0"

    def log_message(self, format: str, *args: Any) -> None:
        # Request method/status are useful locally; headers and bodies are intentionally omitted.
        super().log_message(format, *args)

    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        if path == "/api/health":
            json_response(
                self,
                200,
                {
                    "status": "ok",
                    "service": "Qwen OpsPilot",
                    "provider": PROVIDER,
                    "model": os.getenv("QWEN_MODEL", DEFAULT_MODEL),
                },
            )
            return
        if path == "/api/scenario":
            fixture = load_fixture()
            json_response(self, 200, {"scenario": fixture, "fixture_hash": fixture_hash(fixture)})
            return
        static_entry = STATIC_FILES.get(path)
        if static_entry:
            self._serve_static(*static_entry)
            return
        json_response(self, 404, {"error": {"code": "NOT_FOUND", "message": "Route not found."}})

    def do_POST(self) -> None:
        path = urlsplit(self.path).path
        try:
            body = self._read_json_body()
        except RequestError as error:
            payload: dict[str, Any] = {"error": {"code": error.code, "message": str(error)}}
            if path in {"/api/approve", "/api/reject"}:
                action = "approval_denied" if path == "/api/approve" else "rejection_invalid"
                payload["decision"] = _unchanged_failure_decision(action, str(error))
            json_response(self, error.status, payload)
            return
        if path == "/api/policy-check":
            result = execute_tool_call("run_shell", {"command": "whoami"})
            json_response(self, 200, result)
            return
        if path == "/api/run":
            self._run_investigation(body)
            return
        if path == "/api/approve":
            self._handle_decision(body, "approved")
            return
        if path == "/api/reject":
            self._handle_decision(body, "rejected")
            return
        if path == "/api/report":
            self._handle_report(body)
            return
        json_response(self, 404, {"error": {"code": "NOT_FOUND", "message": "Route not found."}})

    def _read_json_body(self) -> dict[str, Any]:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise RequestError(400, "INVALID_REQUEST", "Invalid Content-Length.") from exc
        if length < 0:
            raise RequestError(400, "INVALID_REQUEST", "Invalid Content-Length.")
        if length > MAX_REQUEST_BYTES:
            raise RequestError(413, "REQUEST_TOO_LARGE", "Request body exceeds 32 KiB.")
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if length and content_type != "application/json":
            raise RequestError(415, "UNSUPPORTED_MEDIA_TYPE", "Content-Type must be application/json.")
        try:
            value = json.loads(
                self.rfile.read(length) or b"{}",
                parse_constant=_reject_json_constant,
            )
        except (UnicodeDecodeError, ValueError, RecursionError) as exc:
            raise RequestError(400, "INVALID_JSON", "Request body must be valid JSON.") from exc
        if not isinstance(value, dict):
            raise RequestError(400, "INVALID_REQUEST", "Request body must be a JSON object.")
        return value

    def _run_investigation(self, body: dict[str, Any]) -> None:
        if set(body) != {"incident_id"} or body.get("incident_id") != "watchdog-window-flash":
            json_response(
                self,
                400,
                {"error": {"code": "INVALID_INCIDENT", "message": "Use the bundled incident ID."}},
            )
            return
        if not RUN_LOCK.acquire(blocking=False):
            json_response(
                self,
                429,
                {"error": {"code": "RUN_IN_PROGRESS", "message": "Another investigation is already running."}},
            )
            return
        try:
            result = run_investigation()
        except QwenError as error:
            json_response(
                self,
                error.status,
                {
                    "status": "failed",
                    "provider": PROVIDER,
                    "model": os.getenv("QWEN_MODEL", DEFAULT_MODEL),
                    "error": {"code": error.code, "message": str(error)},
                },
            )
            return
        except DiagnosisValidationError:
            json_response(
                self,
                502,
                {
                    "status": "failed",
                    "provider": PROVIDER,
                    "model": os.getenv("QWEN_MODEL", DEFAULT_MODEL),
                    "error": {"code": "QWEN_PROVIDER_ERROR", "message": "Qwen diagnosis failed validation."},
                },
            )
            return
        finally:
            RUN_LOCK.release()
        json_response(self, 200, result)

    def _handle_decision(self, body: dict[str, Any], action: str) -> None:
        if set(body) != {"run"}:
            message = "Decision request must contain only the signed run."
            json_response(
                self,
                400,
                {
                    "error": {"code": "INVALID_REQUEST", "message": message},
                    "decision": _unchanged_failure_decision(
                        "approval_denied" if action == "approved" else "rejection_invalid",
                        message,
                    ),
                },
            )
            return
        run = body.get("run")
        try:
            run_core, proposal, fixture = _validate_run_envelope(
                run,
                enforce_approval_expiry=True,
            )
            decision = _issue_decision(run, run_core, proposal, fixture, action)
        except IntegrityValidationError as error:
            json_response(
                self,
                error.status,
                {
                    "error": {"code": error.code, "message": str(error)},
                    "decision": _unchanged_failure_decision(
                        "approval_denied" if action == "approved" else "rejection_invalid",
                        str(error),
                    ),
                },
            )
            return
        json_response(self, 200, decision)

    def _handle_report(self, body: dict[str, Any]) -> None:
        if set(body) != {"run", "decision"}:
            json_response(
                self,
                400,
                {
                    "error": {
                        "code": "INVALID_REQUEST",
                        "message": "Report request requires the signed run and decision.",
                    }
                },
            )
            return
        run = body.get("run")
        try:
            run_core, proposal, fixture = _validate_run_envelope(
                run,
                enforce_approval_expiry=False,
            )
            decision = _validate_decision_envelope(
                run,
                run_core,
                proposal,
                fixture,
                body.get("decision"),
            )
            report = build_markdown_report(run, decision)
        except IntegrityValidationError as error:
            json_response(
                self,
                error.status,
                {"error": {"code": error.code, "message": str(error)}},
            )
            return
        markdown_response(self, report)

    def _serve_static(self, path: Path, content_type: str) -> None:
        try:
            body = path.read_bytes()
        except OSError:
            json_response(self, 500, {"error": {"code": "SERVER_ERROR", "message": "Asset unavailable."}})
            return
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        send_security_headers(self)
        self.end_headers()
        self.wfile.write(body)


def main() -> None:
    host, port = server_binding()
    server = ThreadingHTTPServer((host, port), OpsPilotHandler)
    print(f"Qwen OpsPilot listening on http://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
