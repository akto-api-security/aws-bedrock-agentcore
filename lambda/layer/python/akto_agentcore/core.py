#!/usr/bin/env python3
"""
Akto guardrails interceptor for Amazon Bedrock AgentCore Gateway (MCP target).

Vendored from https://github.com/akto-api-security/aws-bedrock-agentcore
(lambda/interceptor/handler.py). Attached as a REQUEST + RESPONSE interceptor.

Attached to an AgentCore Gateway as a REQUEST + RESPONSE interceptor. It reads
the MCP JSON-RPC body from the interceptor event, sends it to Akto's guardrails
API for validation, and either passes the traffic through, rewrites it, or
short-circuits it with a JSON-RPC error.

Akto contract:
  REQUEST  -> POST {AKTO_DATA_INGESTION_URL}/api/http-proxy?guardrails=true&...
  RESPONSE -> POST {AKTO_DATA_INGESTION_URL}/api/http-proxy?response_guardrails=true&...
  Auth     -> Authorization: <AKTO_API_TOKEN>           (raw token, no "Bearer")
  Result   -> result["data"]["guardrailsResult"]: Allowed / Reason / behaviour
              / Modified / ModifiedPayload

Behaviour at the gateway:
  - AKTO_FAIL_OPEN (default false): on Akto errors, missing config, HITL timeout,
    or poll failure, block the tools/call. Set true to pass traffic through.
  - Allowed=false + behaviour "block" (or unset) -> block (JSON-RPC error).
  - Allowed=false + behaviour "warn"/"alert"      -> allow, log only. There is no
    interactive resubmit path at a gateway, so warn/alert cannot hard-block.
  - behaviour "human_approval" -> poll /api/http-proxy with activityId until
    approved/blocked; unresolved decisions follow AKTO_FAIL_OPEN.
  - Modified=true -> substitute Akto's ModifiedPayload (arg rewrite / redaction).
  - Only `tools/call` is guardrailed; other MCP methods (initialize, tools/list,
    notifications/*, ping) and stream-borne server requests pass through.

Interceptor output contract (AWS docs):
  { "interceptorOutputVersion": "1.0", "mcp": { ... } }
"""

import base64
import binascii
import json
import logging
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, replace
from http import HTTPStatus
from typing import Any, Dict, Optional

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# ---------------------------------------------------------------------------
# Configuration.
# ---------------------------------------------------------------------------
AKTO_DATA_INGESTION_URL = (os.getenv("AKTO_DATA_INGESTION_URL") or "").rstrip("/")
AKTO_API_TOKEN = os.getenv("AKTO_API_TOKEN", "")

AKTO_TIMEOUT = float(os.getenv("AKTO_TIMEOUT_SECONDS", "30"))
AKTO_APPROVAL_WAIT_SECONDS = float(os.getenv("AKTO_APPROVAL_WAIT_SECONDS", "840"))
AKTO_APPROVAL_POLL_SECONDS = float(os.getenv("AKTO_APPROVAL_POLL_SECONDS", "2"))
AKTO_APPROVAL_SAFETY_SECONDS = 5.0
AKTO_CONNECTOR = "agentcore_gateway"   # akto_connector query param + client tag
CONTEXT_SOURCE = "AGENTIC"             # contextSource for policy filtering
INTERCEPTOR_OUTPUT_VERSION = "1.0"
GUARDED_METHODS = {"tools/call"}

# Request headers never forwarded to Akto (secrets).
_SENSITIVE_HEADERS = {"authorization", "cookie", "set-cookie", "x-api-key", "x-amz-security-token"}


def _fail_open() -> bool:
    """AKTO_FAIL_OPEN defaults to false (fail closed)."""
    raw = (os.getenv("AKTO_FAIL_OPEN") or "false").strip().lower()
    return raw in ("1", "true", "yes", "on")


# ---------------------------------------------------------------------------
# Akto HTTP-proxy client
# ---------------------------------------------------------------------------
def _build_http_proxy_url(*, guardrails: bool = False, response_guardrails: bool = False,
                          ingest_data: bool = False) -> str:
    params = []
    if guardrails:
        params.append("guardrails=true")
    if response_guardrails:
        params.append("response_guardrails=true")
    params.append(f"akto_connector={AKTO_CONNECTOR}")
    if ingest_data:
        params.append("ingest_data=true")
    return f"{AKTO_DATA_INGESTION_URL}/api/http-proxy?{'&'.join(params)}"


def _post_json(url: str, payload: Dict[str, Any]) -> Any:
    headers = {"Content-Type": "application/json"}
    if AKTO_API_TOKEN:
        headers["Authorization"] = AKTO_API_TOKEN
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode("utf-8"), headers=headers, method="POST"
    )
    start = time.time()
    try:
        with urllib.request.urlopen(req, timeout=AKTO_TIMEOUT) as resp:
            raw = resp.read().decode("utf-8")
            duration_ms = int((time.time() - start) * 1000)
            status = resp.getcode()
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        duration_ms = int((time.time() - start) * 1000)
        preview = raw if len(raw) <= 32000 else raw[:32000] + "...[truncated]"
        logger.error(
            "Akto response: status=%s duration=%dms size=%d body=%s",
            exc.code, duration_ms, len(raw), preview,
        )
        raise

    preview = raw if len(raw) <= 32000 else raw[:32000] + "...[truncated]"
    logger.info(
        "Akto response: status=%s duration=%dms size=%d body=%s",
        status, duration_ms, len(raw), preview,
    )
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return raw


@dataclass(frozen=True)
class GuardrailsResult:
    allowed: bool = True
    reason: str = ""
    behaviour: str = ""
    modified: bool = False
    modified_payload: Any = ""
    status: str = ""
    activity_id: str = ""


def _unresolved_approval(initial: GuardrailsResult, message: str) -> GuardrailsResult:
    """HITL timeout / poll error / missing id: allow only when AKTO_FAIL_OPEN=true."""
    if _fail_open():
        logger.error("%s — failing open", message)
        return replace(initial, allowed=True)
    logger.error("%s — failing closed", message)
    reason = initial.reason or "Human approval unresolved"
    return replace(initial, allowed=False, reason=reason)


def _parse_guardrails_result(result: Any) -> GuardrailsResult:
    """Parse validation and approval-poll responses.

    The HTTP proxy wraps results under data.guardrailsResult. Direct service
    responses and tests may provide guardrailsResult at the top level. Normal
    validation fields use title case, while PR #6289's human-approval fields
    use lower case, so both forms are accepted.
    """
    if not isinstance(result, dict):
        raise ValueError("Akto response is not a JSON object")
    data = result.get("data", result)
    gr = data.get("guardrailsResult", data) if isinstance(data, dict) else {}
    if not isinstance(gr, dict) or not (
        "Allowed" in gr or "allowed" in gr or "behaviour" in gr or "Behaviour" in gr
    ):
        raise ValueError("Akto response is missing guardrailsResult")
    allowed = gr.get("Allowed", gr.get("allowed", True))
    reason = gr.get("Reason", gr.get("reason", ""))
    behaviour = gr.get("behaviour", "") or gr.get("Behaviour", "")
    modified = gr.get("Modified", gr.get("modified", False))
    modified_payload = gr.get("ModifiedPayload", gr.get("modifiedPayload", ""))
    status = gr.get("status", gr.get("Status", ""))
    activity_id = gr.get("activityId", gr.get("ActivityId", gr.get("ActivityID", "")))
    return GuardrailsResult(
        allowed=bool(allowed),
        reason=str(reason or ""),
        behaviour=str(behaviour or ""),
        modified=bool(modified),
        modified_payload=modified_payload,
        status=str(status or "").strip().lower(),
        activity_id=str(activity_id or ""),
    )


def _approval_deadline(context: Any) -> float:
    """Return a monotonic deadline bounded by this Lambda invocation."""
    wait_seconds = max(0.0, AKTO_APPROVAL_WAIT_SECONDS)
    get_remaining = getattr(context, "get_remaining_time_in_millis", None)
    if callable(get_remaining):
        remaining = max(0.0, get_remaining() / 1000.0 - AKTO_APPROVAL_SAFETY_SECONDS)
        wait_seconds = min(wait_seconds, remaining)
    return time.monotonic() + wait_seconds


def _resolve_human_approval(
    initial: GuardrailsResult, guardrails_url: str, context: Any
) -> GuardrailsResult:
    """Poll the same HTTP-proxy route until an admin approves or blocks.

    Unresolved HITL follows AKTO_FAIL_OPEN (default fail closed).
    """
    if initial.behaviour.strip().lower() != "human_approval":
        return initial
    if initial.status == "approved":
        return replace(initial, allowed=True)
    if initial.status == "blocked":
        return replace(initial, allowed=False)
    if not initial.activity_id:
        return _unresolved_approval(initial, "Human approval response missing activityId")

    deadline = _approval_deadline(context)
    poll_interval = max(0.1, AKTO_APPROVAL_POLL_SECONDS)
    logger.info(
        "Waiting for human approval: activityId=%s max_wait=%.1fs fail_open=%s",
        initial.activity_id,
        max(0.0, deadline - time.monotonic()),
        _fail_open(),
    )

    while time.monotonic() < deadline:
        try:
            polled = _parse_guardrails_result(
                _post_json(guardrails_url, {"activityId": initial.activity_id})
            )
        except Exception as exc:
            return _unresolved_approval(
                initial,
                f"Human approval poll failed for activityId={initial.activity_id}: {exc}",
            )

        if polled.status == "approved":
            logger.info("Human approval granted: activityId=%s", initial.activity_id)
            return replace(
                polled,
                allowed=True,
                reason=polled.reason or initial.reason,
                activity_id=initial.activity_id,
            )
        if polled.status == "blocked":
            logger.warning("Human approval blocked: activityId=%s", initial.activity_id)
            return replace(
                polled,
                allowed=False,
                reason=polled.reason or initial.reason,
                activity_id=initial.activity_id,
            )
        if polled.status != "pending":
            return _unresolved_approval(
                initial,
                f"Unknown human approval status={polled.status!r} for activityId={initial.activity_id}",
            )

        sleep_seconds = min(poll_interval, max(0.0, deadline - time.monotonic()))
        if sleep_seconds:
            time.sleep(sleep_seconds)

    return _unresolved_approval(
        initial,
        f"Human approval timed out for activityId={initial.activity_id}",
    )


# ---------------------------------------------------------------------------
# Payload construction
# ---------------------------------------------------------------------------
def _is_mcp_body(body: Any) -> bool:
    """MCP traffic is JSON-RPC 2.0 (matches the runtime's McpRequestResponseUtils
    .isMcpRequest). A plain LLM / AI-agent call has no `jsonrpc` envelope."""
    return isinstance(body, dict) and str(body.get("jsonrpc", "")) == "2.0"


def _build_tags(is_mcp: bool) -> Dict[str, str]:
    """Tag MCP traffic as an MCP server/client; tag everything else (LLM / AI
    agent calls) as gen-ai."""
    if is_mcp:
        return {"mcp-server": "MCP Server", "service": AKTO_CONNECTOR}
    return {"gen-ai": "Gen AI", "service": AKTO_CONNECTOR}


def _clean_headers(headers: Any) -> Dict[str, str]:
    """Real gateway headers minus secrets. Includes Mcp-Session-Id (used by the
    guardrails service to group by session) when passRequestHeaders is enabled."""
    if not isinstance(headers, dict):
        return {}
    return {k: v for k, v in headers.items()
            if isinstance(k, str) and k.lower() not in _SENSITIVE_HEADERS}


def _ensure_host(headers: Dict[str, str], is_mcp: bool) -> Dict[str, str]:
    """Akto groups traffic into API collections by the `host` header. If the
    gateway didn't forward one, add a stable default identifying this source."""
    if any(isinstance(k, str) and k.lower() == "host" for k in headers):
        return headers
    suffix = "mcp" if is_mcp else "ai-agent"
    return {**headers, "host": f"{AKTO_CONNECTOR}.{suffix}"}


def _client_ip(headers: Dict[str, str]) -> str:
    for key in ("X-Forwarded-For", "x-forwarded-for", "X-Real-Ip", "x-real-ip"):
        val = headers.get(key)
        if val:
            return val.split(",")[0].strip()
    return ""


def _status_phrase(code: int) -> str:
    """HTTP reason phrase for a status code: 200 -> 'OK', 404 -> 'Not Found'."""
    try:
        return HTTPStatus(code).phrase
    except ValueError:
        return ""


def _build_ingest_payload(*, request_payload: str, response_payload: str,
                          request_headers: Dict[str, str], response_headers: Dict[str, str],
                          status_code: Optional[int], is_mcp: bool,
                          path: str = "/mcp", method: str = "POST") -> Dict[str, Any]:
    """HTTP-proxy IngestDataBatch shape expected by the guardrails service
    (models.IngestDataBatch). Carries the real gateway headers/status, not
    synthesised values."""
    tags = _build_tags(is_mcp)
    # Request phase has no response yet -> default to 200/OK; response phase
    # carries the real gateway status. statusCode is numeric; status is the
    # HTTP reason phrase ("OK", "Not Found", ...).
    code = status_code if status_code is not None else 200
    request_headers = _ensure_host(request_headers, is_mcp)
    return {
        "path": path,
        "requestHeaders": json.dumps(request_headers),
        "responseHeaders": json.dumps(response_headers),
        "method": method,
        "requestPayload": request_payload,
        "responsePayload": response_payload,
        "ip": _client_ip(request_headers),
        "time": str(int(time.time() * 1000)),
        "statusCode": code,
        "type": "HTTP/1.1",
        "status": _status_phrase(code),
        "akto_account_id": "1000000",
        "akto_vxlan_id": 0,
        "is_pending": "false",
        "source": "MIRRORING",
        "tag": json.dumps(tags),
        "metadata": json.dumps(tags),
        "contextSource": CONTEXT_SOURCE,
    }


# ---------------------------------------------------------------------------
# Decision helpers
# ---------------------------------------------------------------------------
def _should_block(allowed: bool, behaviour: str) -> bool:
    """A gateway has no interactive resubmit/confirm path, so only a hard
    'block' (or an unset behaviour on a denied verdict) blocks. 'warn' and
    'alert' allow the traffic and rely on server-side logging."""
    if allowed:
        return False
    b = str(behaviour or "").strip().lower()
    if b in ("warn", "alert"):
        logger.info("Guardrail behaviour=%s — allowing (logged only, no block at gateway)", b)
        return False
    return True


def _block_message(reason: str, *, is_response: bool) -> str:
    subject = "Tool result" if is_response else "Tool request"
    return f"{subject} blocked by Akto policy: {reason}" if reason else \
           f"{subject} blocked by Akto policy"


def _maybe_parse(payload: Any) -> Optional[dict]:
    """ModifiedPayload may be a JSON string or already a dict."""
    if isinstance(payload, dict):
        return payload
    if isinstance(payload, str) and payload.strip():
        try:
            parsed = json.loads(payload)
            return parsed if isinstance(parsed, dict) else None
        except json.JSONDecodeError:
            return None
    return None


# ---------------------------------------------------------------------------
# Interceptor output builders
# ---------------------------------------------------------------------------
def _jsonrpc_error(request_id: Any, message: str, status_code: int = 403) -> Dict[str, Any]:
    return {
        "interceptorOutputVersion": INTERCEPTOR_OUTPUT_VERSION,
        "mcp": {
            "transformedGatewayResponse": {
                "statusCode": status_code,
                "body": {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {"code": -32000, "message": message},
                },
            }
        },
    }


def _passthrough_request(body: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "interceptorOutputVersion": INTERCEPTOR_OUTPUT_VERSION,
        "mcp": {"transformedGatewayRequest": {"body": body}},
    }


def _passthrough_response(body: Dict[str, Any], status_code: int) -> Dict[str, Any]:
    return {
        "interceptorOutputVersion": INTERCEPTOR_OUTPUT_VERSION,
        "mcp": {"transformedGatewayResponse": {"body": body, "statusCode": status_code}},
    }


# ---------------------------------------------------------------------------
# HTTP-family targets (AgentCore Runtime, inference, and custom/passthrough)
#
# AWS contract:
# https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-interceptors-types.html
#
# These targets use event["http"], and bodies are base64 strings rather than
# parsed JSON. REQUEST and RESPONSE interception is supported only in buffered
# mode; HTTP streaming bypasses interceptors. Lambda's synchronous request plus
# response payload is limited to 6 MB. A configured RESPONSE_BODY payload
# filter makes body null, in which case content scanning is impossible and the
# response must pass through unchanged.
# ---------------------------------------------------------------------------
def _http_passthrough() -> Dict[str, Any]:
    """An empty HTTP transform preserves the original request or response."""
    return {
        "interceptorOutputVersion": INTERCEPTOR_OUTPUT_VERSION,
        "http": {},
    }


def _decode_http_body(encoded: Any) -> str:
    if not isinstance(encoded, str) or not encoded:
        raise ValueError("HTTP interceptor body is empty")
    try:
        raw = base64.b64decode(encoded, validate=True)
        return raw.decode("utf-8")
    except (binascii.Error, UnicodeDecodeError) as exc:
        raise ValueError("HTTP interceptor body is not valid base64 UTF-8") from exc


def _encode_http_body(payload: Any) -> str:
    if isinstance(payload, bytes):
        raw = payload
    elif isinstance(payload, str):
        raw = payload.encode("utf-8")
    else:
        raw = json.dumps(payload).encode("utf-8")
    return base64.b64encode(raw).decode("ascii")


def _http_block_message(reason: str, *, is_response: bool) -> str:
    subject = "Agent response" if is_response else "Agent request"
    return f"{subject} blocked by Akto policy: {reason}" if reason else \
           f"{subject} blocked by Akto policy"


def _http_block_response(reason: str, *, is_response: bool,
                         status_code: int = 403) -> Dict[str, Any]:
    body = {
        "error": {
            "code": "AKTO_GUARDRAIL_BLOCKED",
            "message": _http_block_message(reason, is_response=is_response),
        }
    }
    return {
        "interceptorOutputVersion": INTERCEPTOR_OUTPUT_VERSION,
        "http": {
            "transformedGatewayResponse": {
                "statusCode": status_code,
                "contentType": "application/json",
                "body": _encode_http_body(body),
            }
        },
    }


def _http_modified_body(payload: Any) -> Optional[str]:
    if isinstance(payload, str) and payload:
        return payload
    if isinstance(payload, (dict, list)):
        return json.dumps(payload)
    return None


def _handle_http_request(http: Dict[str, Any], context: Any = None) -> Dict[str, Any]:
    gateway_request = http.get("gatewayRequest", {}) or {}
    encoded_body = gateway_request.get("body")
    path = str(gateway_request.get("path") or "/")
    method = str(gateway_request.get("httpMethod") or "POST").upper()
    if not encoded_body:
        return _http_passthrough()

    try:
        request_body = _decode_http_body(encoded_body)
    except ValueError as exc:
        logger.error("Invalid HTTP REQUEST body — failing %s: %s",
                     "open" if _fail_open() else "closed", exc)
        return _http_passthrough() if _fail_open() else \
            _http_block_response(str(exc), is_response=False)

    if not AKTO_DATA_INGESTION_URL:
        logger.warning("AKTO_DATA_INGESTION_URL not set")
        return _http_passthrough() if _fail_open() else \
            _http_block_response("Akto not configured", is_response=False)

    logger.info("Guardrailing HTTP REQUEST: method=%s path=%s", method, path)
    try:
        payload = _build_ingest_payload(
            request_payload=request_body,
            response_payload=json.dumps({}),
            request_headers=_clean_headers(gateway_request.get("headers")),
            response_headers={},
            status_code=None,
            is_mcp=False,
            path=path,
            method=method,
        )
        guardrails_url = _build_http_proxy_url(guardrails=True, ingest_data=True)
        result = _parse_guardrails_result(_post_json(guardrails_url, payload))
        logger.info(
            "Guardrails parsed HTTP REQUEST: allowed=%s behaviour=%s status=%s "
            "activityId=%s modified=%s reason=%s",
            result.allowed, result.behaviour, result.status, result.activity_id,
            result.modified, result.reason,
        )
        result = _resolve_human_approval(result, guardrails_url, context)
    except Exception as exc:
        logger.error("Akto guardrails error (HTTP REQUEST) — failing %s: %s",
                     "open" if _fail_open() else "closed", exc)
        return _http_passthrough() if _fail_open() else \
            _http_block_response("Akto guardrails unavailable", is_response=False)

    if _should_block(result.allowed, result.behaviour):
        logger.warning("BLOCKING HTTP REQUEST %s %s: %s", method, path, result.reason)
        return _http_block_response(result.reason, is_response=False)

    if result.modified and result.modified_payload:
        modified = _http_modified_body(result.modified_payload)
        if modified is not None:
            logger.info("Applying guardrail-modified HTTP REQUEST: %s %s", method, path)
            return {
                "interceptorOutputVersion": INTERCEPTOR_OUTPUT_VERSION,
                "http": {"transformedGatewayRequest": {"body": _encode_http_body(modified)}},
            }
    return _http_passthrough()


def _handle_http_response(http: Dict[str, Any], context: Any = None) -> Dict[str, Any]:
    gateway_response = http.get("gatewayResponse", {}) or {}
    gateway_request = http.get("gatewayRequest", {}) or {}
    encoded_body = gateway_response.get("body")
    if not encoded_body:
        return _http_passthrough()

    path = str(gateway_request.get("path") or "/")
    method = str(gateway_request.get("httpMethod") or "POST").upper()
    status_code = int(gateway_response.get("statusCode") or 200)
    content_type = str(gateway_response.get("contentType") or "application/json")
    try:
        response_body = _decode_http_body(encoded_body)
    except ValueError as exc:
        logger.error("Invalid HTTP RESPONSE body — failing %s: %s",
                     "open" if _fail_open() else "closed", exc)
        return _http_passthrough() if _fail_open() else \
            _http_block_response(str(exc), is_response=True)

    if not AKTO_DATA_INGESTION_URL:
        return _http_passthrough() if _fail_open() else \
            _http_block_response("Akto not configured", is_response=True)

    logger.info("Guardrailing HTTP RESPONSE: status=%s path=%s", status_code, path)
    try:
        # AWS documents gatewayRequest as null for HTTP RESPONSE interception.
        # Akto still requires requestPayload to contain valid JSON.
        request_payload = json.dumps({})
        if gateway_request.get("body"):
            request_payload = _decode_http_body(gateway_request["body"])
        payload = _build_ingest_payload(
            request_payload=request_payload,
            response_payload=response_body,
            request_headers=_clean_headers(gateway_request.get("headers")),
            response_headers=_clean_headers(gateway_response.get("headers")),
            status_code=status_code,
            is_mcp=False,
            path=path,
            method=method,
        )
        guardrails_url = _build_http_proxy_url(response_guardrails=True)
        result = _parse_guardrails_result(_post_json(guardrails_url, payload))
        logger.info(
            "Guardrails parsed HTTP RESPONSE: allowed=%s behaviour=%s status=%s "
            "activityId=%s modified=%s reason=%s",
            result.allowed, result.behaviour, result.status, result.activity_id,
            result.modified, result.reason,
        )
        result = _resolve_human_approval(result, guardrails_url, context)
    except Exception as exc:
        logger.error("Akto guardrails error (HTTP RESPONSE) — failing %s: %s",
                     "open" if _fail_open() else "closed", exc)
        return _http_passthrough() if _fail_open() else \
            _http_block_response("Akto guardrails unavailable", is_response=True)

    if _should_block(result.allowed, result.behaviour):
        return _http_block_response(result.reason, is_response=True)
    if result.modified and result.modified_payload:
        modified = _http_modified_body(result.modified_payload)
        if modified is not None:
            return {
                "interceptorOutputVersion": INTERCEPTOR_OUTPUT_VERSION,
                "http": {
                    "transformedGatewayResponse": {
                        "statusCode": status_code,
                        "contentType": content_type,
                        "body": _encode_http_body(modified),
                    }
                },
            }
    return _http_passthrough()


# ---------------------------------------------------------------------------
# REQUEST interceptor
# ---------------------------------------------------------------------------
def _handle_request(mcp: Dict[str, Any], context: Any = None) -> Dict[str, Any]:
    gateway_request = mcp.get("gatewayRequest", {}) or {}
    body = gateway_request.get("body", {}) or {}
    method = body.get("method", "")
    request_id = body.get("id")

    if method not in GUARDED_METHODS:
        logger.info("Pass-through (unguarded method): %s", method or "unknown")
        return _passthrough_request(body)

    if not AKTO_DATA_INGESTION_URL:
        logger.warning("AKTO_DATA_INGESTION_URL not set")
        if _fail_open():
            return _passthrough_request(body)
        return _jsonrpc_error(request_id, _block_message("Akto not configured", is_response=False))

    tool_name = (body.get("params") or {}).get("name", "unknown")
    logger.info("Guardrailing REQUEST tools/call: %s", tool_name)

    try:
        payload = _build_ingest_payload(
            request_payload=json.dumps(body),
            response_payload=json.dumps({}),
            request_headers=_clean_headers(gateway_request.get("headers")),
            response_headers={},
            status_code=None,
            is_mcp=_is_mcp_body(body),
        )
        guardrails_url = _build_http_proxy_url(guardrails=True, ingest_data=True)
        raw_result = _post_json(guardrails_url, payload)
        result = _parse_guardrails_result(raw_result)
        logger.info(
            "Guardrails parsed REQUEST: allowed=%s behaviour=%s status=%s activityId=%s modified=%s reason=%s",
            result.allowed, result.behaviour, result.status, result.activity_id,
            result.modified, result.reason,
        )
        result = _resolve_human_approval(result, guardrails_url, context)
    except Exception as e:
        logger.error("Akto guardrails error (REQUEST) — failing %s: %s",
                     "open" if _fail_open() else "closed", e)
        if _fail_open():
            return _passthrough_request(body)
        return _jsonrpc_error(
            request_id,
            _block_message("Akto guardrails unavailable", is_response=False),
        )

    if _should_block(result.allowed, result.behaviour):
        logger.warning("BLOCKING tools/call %s: %s", tool_name, result.reason)
        return _jsonrpc_error(request_id, _block_message(result.reason, is_response=False))

    # Apply guardrail-modified arguments if Akto rewrote them.
    if result.modified and result.modified_payload:
        parsed = _maybe_parse(result.modified_payload)
        new_args = ((parsed or {}).get("params") or {}).get("arguments")
        if isinstance(new_args, dict):
            logger.info("Applying guardrail-modified arguments for %s", tool_name)
            new_body = dict(body)
            new_body["params"] = {**(body.get("params") or {}), "arguments": new_args}
            return _passthrough_request(new_body)
        logger.warning("Modified payload missing params.arguments — passing original through")

    return _passthrough_request(body)


# ---------------------------------------------------------------------------
# RESPONSE interceptor
# ---------------------------------------------------------------------------
def _handle_response(mcp: Dict[str, Any], context: Any = None) -> Dict[str, Any]:
    gateway_request = mcp.get("gatewayRequest", {}) or {}
    gateway_response = mcp.get("gatewayResponse", {}) or {}
    req_body = gateway_request.get("body", {}) or {}
    resp_body = gateway_response.get("body", {}) or {}
    status_code = gateway_response.get("statusCode", 200)
    request_id = resp_body.get("id", req_body.get("id"))
    is_streaming = bool(gateway_response.get("isStreamingResponse"))

    # Only guardrail tool-call results; pass through lifecycle / list responses.
    if req_body.get("method") not in GUARDED_METHODS:
        return _passthrough_response(resp_body, status_code)

    # Server-initiated requests on a stream (elicitation/create, sampling/...)
    # are not tool results — let them through.
    if "method" in resp_body:
        return _passthrough_response(resp_body, status_code)

    if not AKTO_DATA_INGESTION_URL:
        logger.warning("AKTO_DATA_INGESTION_URL not set")
        if _fail_open():
            return _passthrough_response(resp_body, status_code)
        return _jsonrpc_error(
            request_id,
            _block_message("Akto not configured", is_response=True),
            status_code=200 if is_streaming else status_code,
        )

    tool_name = (req_body.get("params") or {}).get("name", "unknown")
    logger.info("Guardrailing RESPONSE tools/call result: %s (streaming=%s)",
                tool_name, is_streaming)

    try:
        payload = _build_ingest_payload(
            request_payload=json.dumps(req_body),
            response_payload=json.dumps(resp_body),
            request_headers=_clean_headers(gateway_request.get("headers")),
            response_headers=_clean_headers(gateway_response.get("headers")),
            status_code=status_code,
            is_mcp=_is_mcp_body(req_body),
        )
        guardrails_url = _build_http_proxy_url(response_guardrails=True)
        raw_result = _post_json(guardrails_url, payload)
        result = _parse_guardrails_result(raw_result)
        logger.info(
            "Guardrails parsed RESPONSE: allowed=%s behaviour=%s status=%s activityId=%s modified=%s reason=%s",
            result.allowed, result.behaviour, result.status, result.activity_id,
            result.modified, result.reason,
        )
        result = _resolve_human_approval(result, guardrails_url, context)
    except Exception as e:
        logger.error("Akto guardrails error (RESPONSE) — failing %s: %s",
                     "open" if _fail_open() else "closed", e)
        if _fail_open():
            return _passthrough_response(resp_body, status_code)
        return _jsonrpc_error(
            request_id,
            _block_message("Akto guardrails unavailable", is_response=True),
            status_code=200 if is_streaming else status_code,
        )

    if _should_block(result.allowed, result.behaviour):
        logger.warning("BLOCKING tools/call result %s: %s", tool_name, result.reason)
        # On a subsequent streaming event statusCode is ignored by the gateway,
        # but the error body still replaces the event.
        return _jsonrpc_error(request_id, _block_message(result.reason, is_response=True),
                              status_code=200 if is_streaming else status_code)

    # Redact / rewrite the result if Akto returned a modified payload.
    if result.modified and result.modified_payload:
        parsed = _maybe_parse(result.modified_payload)
        if parsed is not None:
            logger.info("Applying guardrail-modified result for %s", tool_name)
            new_body = parsed if "jsonrpc" in parsed else {
                "jsonrpc": "2.0", "id": request_id, "result": parsed.get("result", parsed)
            }
            return _passthrough_response(new_body, status_code)
        logger.warning("Modified response payload not JSON — passing original through")

    return _passthrough_response(resp_body, status_code)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def lambda_handler(event, context):
    """Dispatch AWS's MCP and HTTP-family interceptor contracts.

    HTTP-family means AgentCore Runtime, inference, and custom/passthrough
    targets. See:
    https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-interceptors-types.html
    """
    try:
        if isinstance(event.get("http"), dict):
            http = event["http"]
            if http.get("gatewayResponse") is not None:
                return _handle_http_response(http, context)
            return _handle_http_request(http, context)

        mcp = event.get("mcp", {}) or {}
        if mcp.get("gatewayResponse") is not None:
            return _handle_response(mcp, context)
        return _handle_request(mcp, context)
    except Exception as e:
        logger.error("Interceptor fatal error — failing %s: %s",
                     "open" if _fail_open() else "closed", e)
        if isinstance(event.get("http"), dict):
            return _http_passthrough() if _fail_open() else \
                _http_block_response("interceptor error", is_response=(
                    event["http"].get("gatewayResponse") is not None
                ))

        mcp = event.get("mcp", {}) or {}
        if mcp.get("gatewayResponse") is not None:
            gr = mcp.get("gatewayResponse", {}) or {}
            if _fail_open():
                return _passthrough_response(gr.get("body", {}) or {}, gr.get("statusCode", 200))
            req_body = (mcp.get("gatewayRequest", {}) or {}).get("body", {}) or {}
            resp_body = gr.get("body", {}) or {}
            request_id = resp_body.get("id", req_body.get("id"))
            return _jsonrpc_error(
                request_id,
                _block_message("interceptor error", is_response=True),
                status_code=gr.get("statusCode", 200),
            )
        req_body = (mcp.get("gatewayRequest", {}) or {}).get("body", {}) or {}
        if _fail_open():
            return _passthrough_request(req_body)
        return _jsonrpc_error(
            req_body.get("id"),
            _block_message("interceptor error", is_response=False),
        )
