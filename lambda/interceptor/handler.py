#!/usr/bin/env python3
"""
Akto guardrails interceptor for Amazon Bedrock AgentCore Gateway (MCP target).

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
  - Fail-open: any Akto error / unreachable endpoint -> allow, pass through.
  - Allowed=false + behaviour "block" (or unset) -> block (JSON-RPC error).
  - Allowed=false + behaviour "warn"/"alert"      -> allow, log only. There is no
    interactive resubmit path at a gateway, so warn/alert cannot hard-block.
  - Modified=true -> substitute Akto's ModifiedPayload (arg rewrite / redaction).
  - Only `tools/call` is guardrailed; other MCP methods (initialize, tools/list,
    notifications/*, ping) and stream-borne server requests pass through.

Interceptor output contract (AWS docs):
  { "interceptorOutputVersion": "1.0", "mcp": { ... } }
"""

import json
import logging
import os
import time
import urllib.request
from http import HTTPStatus
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# ---------------------------------------------------------------------------
# Configuration. Only the two Akto endpoint settings are environment-driven.
# ---------------------------------------------------------------------------
AKTO_DATA_INGESTION_URL = (os.getenv("AKTO_DATA_INGESTION_URL") or "").rstrip("/")
AKTO_API_TOKEN = os.getenv("AKTO_API_TOKEN", "")

AKTO_TIMEOUT = 5.0
AKTO_CONNECTOR = "agentcore_gateway"   # akto_connector query param + client tag
CONTEXT_SOURCE = "AGENTIC"             # contextSource for policy filtering
INTERCEPTOR_OUTPUT_VERSION = "1.0"
GUARDED_METHODS = {"tools/call"}

# Request headers never forwarded to Akto (secrets).
_SENSITIVE_HEADERS = {"authorization", "cookie", "set-cookie", "x-api-key", "x-amz-security-token"}


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
    with urllib.request.urlopen(req, timeout=AKTO_TIMEOUT) as resp:
        raw = resp.read().decode("utf-8")
        logger.info("Akto response: status=%s duration=%dms size=%d",
                    resp.getcode(), int((time.time() - start) * 1000), len(raw))
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return raw


def _parse_guardrails_result(result: Any) -> Tuple[bool, str, str, bool, str]:
    """Extract (allowed, reason, behaviour, modified, modified_payload) from
    result["data"]["guardrailsResult"]. Defaults to allow on any odd shape."""
    data = result.get("data", {}) if isinstance(result, dict) else {}
    gr = data.get("guardrailsResult", {}) if isinstance(data, dict) else {}
    if not isinstance(gr, dict):
        return True, "", "", False, ""
    allowed = gr.get("Allowed", True)
    reason = gr.get("Reason", "")
    behaviour = gr.get("behaviour", "") or gr.get("Behaviour", "")
    modified = gr.get("Modified", False)
    modified_payload = gr.get("ModifiedPayload", "")
    return allowed, reason, behaviour, modified, modified_payload


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
                          status_code: Optional[int], is_mcp: bool) -> Dict[str, Any]:
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
        "path": "/mcp",
        "requestHeaders": json.dumps(request_headers),
        "responseHeaders": json.dumps(response_headers),
        "method": "POST",
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
# REQUEST interceptor
# ---------------------------------------------------------------------------
def _handle_request(mcp: Dict[str, Any]) -> Dict[str, Any]:
    gateway_request = mcp.get("gatewayRequest", {}) or {}
    body = gateway_request.get("body", {}) or {}
    method = body.get("method", "")
    request_id = body.get("id")

    if method not in GUARDED_METHODS:
        logger.info("Pass-through (unguarded method): %s", method or "unknown")
        return _passthrough_request(body)

    if not AKTO_DATA_INGESTION_URL:
        logger.warning("AKTO_DATA_INGESTION_URL not set — fail-open pass-through")
        return _passthrough_request(body)

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
        result = _post_json(_build_http_proxy_url(guardrails=True, ingest_data=True), payload)
        allowed, reason, behaviour, modified, modified_payload = _parse_guardrails_result(result)
    except Exception as e:  # fail-open
        logger.error("Akto guardrails error (REQUEST) — failing open: %s", e)
        return _passthrough_request(body)

    if _should_block(allowed, behaviour):
        logger.warning("BLOCKING tools/call %s: %s", tool_name, reason)
        return _jsonrpc_error(request_id, _block_message(reason, is_response=False))

    # Apply guardrail-modified arguments if Akto rewrote them.
    if modified and modified_payload:
        parsed = _maybe_parse(modified_payload)
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
def _handle_response(mcp: Dict[str, Any]) -> Dict[str, Any]:
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
        logger.warning("AKTO_DATA_INGESTION_URL not set — fail-open pass-through")
        return _passthrough_response(resp_body, status_code)

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
        result = _post_json(_build_http_proxy_url(response_guardrails=True), payload)
        allowed, reason, behaviour, modified, modified_payload = _parse_guardrails_result(result)
    except Exception as e:  # fail-open
        logger.error("Akto guardrails error (RESPONSE) — failing open: %s", e)
        return _passthrough_response(resp_body, status_code)

    if _should_block(allowed, behaviour):
        logger.warning("BLOCKING tools/call result %s: %s", tool_name, reason)
        # On a subsequent streaming event statusCode is ignored by the gateway,
        # but the error body still replaces the event.
        return _jsonrpc_error(request_id, _block_message(reason, is_response=True),
                              status_code=200 if is_streaming else status_code)

    # Redact / rewrite the result if Akto returned a modified payload.
    if modified and modified_payload:
        parsed = _maybe_parse(modified_payload)
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
    """REQUEST vs RESPONSE is distinguished by presence of a non-null
    gatewayResponse in the mcp event (per AWS docs)."""
    try:
        mcp = event.get("mcp", {}) or {}
        if mcp.get("gatewayResponse") is not None:
            return _handle_response(mcp)
        return _handle_request(mcp)
    except Exception as e:  # last-resort fail-open
        logger.error("Interceptor fatal error — failing open: %s", e)
        mcp = event.get("mcp", {}) or {}
        if mcp.get("gatewayResponse") is not None:
            gr = mcp.get("gatewayResponse", {}) or {}
            return _passthrough_response(gr.get("body", {}) or {}, gr.get("statusCode", 200))
        return _passthrough_request((mcp.get("gatewayRequest", {}) or {}).get("body", {}) or {})
