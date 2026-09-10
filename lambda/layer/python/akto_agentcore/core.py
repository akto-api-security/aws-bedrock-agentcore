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
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, replace
from http import HTTPStatus
from typing import Any, Dict, Optional

from .agentcore_lookup import (account_id_from_context, agent_for_role,
                               gateway_role_arn, role_name_from_principal)
from .gateway_naming import derive_gateway_name, extract_gateway_id_from_host
from .iam_permissions import get_role_security_profile

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

# Matches the discovery pipeline in akto_aws_bedrock_discovery, so a gateway AKTO
# discovered and the traffic flowing through it group together in the dashboard.
AKTO_SOURCE = os.getenv("AKTO_SOURCE", "AWS_BEDROCK")
AGENT_TYPE = "AGENTCORE_GATEWAY"
AWS_REGION = os.getenv("AWS_REGION", "")
# The interceptor event's identity shape is not documented for AWS_IAM gateways.
# Logged once per container so a deployment can confirm what it actually gets
# instead of guessing; set to "false" once you have seen it.
LOG_REQUEST_CONTEXT = os.getenv("AKTO_LOG_REQUEST_CONTEXT", "true").lower() != "false"
# Logs the exact body POSTed to AKTO. Off by default: the payload contains the
# prompt and the tool result, which is the traffic itself. For debugging a
# deployment, not for steady state.
LOG_PAYLOAD = os.getenv("AKTO_LOG_PAYLOAD", "false").lower() == "true"

# Set once per invocation from the event and the Lambda context, because
# _build_ingest_payload is reached from four call sites that would otherwise
# each have to thread them through.
_INVOCATION: Dict[str, str] = {"principal": "", "account_id": ""}
_context_logged = False

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


def _log_payload(url: str, payload: Dict[str, Any]) -> None:
    """Dump what is about to be sent, when explicitly enabled."""
    if not LOG_PAYLOAD:
        return
    try:
        leg = "REQUEST+ingest" if "ingest_data=true" in url else "RESPONSE"
        logger.info("AKTO payload [%s] -> %s\n%s", leg, url, json.dumps(payload)[:20000])
    except Exception as exc:
        logger.warning("Could not log payload: %s", exc)


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


def _caller_principal(event: Dict[str, Any]) -> str:
    """The identity of whoever called the gateway, from the interceptor event.

    AWS's interceptor example reads `requestContext.identity`, but documents no
    shape for an AWS_IAM-authorized gateway, so several plausible keys are tried
    in order of usefulness: an ARN names the role outright, while a bare user id
    may or may not. Returns "" rather than guessing when nothing looks like an
    identity — an unattributed call is better than a wrongly attributed one.
    """
    contexts = []
    for holder in (event, event.get("mcp") or {}, event.get("http") or {}):
        if isinstance(holder, dict) and isinstance(holder.get("requestContext"), dict):
            contexts.append(holder["requestContext"])
    for rc in contexts:
        identity = rc.get("identity") if isinstance(rc.get("identity"), dict) else {}
        for source in (identity, rc):
            for key in ("callerArn", "userArn", "arn", "principalArn", "caller",
                        "principalId", "userId", "user"):
                value = source.get(key)
                if isinstance(value, str) and value.strip():
                    return value.strip()
    return ""


def _log_request_context_once(event: Dict[str, Any]) -> None:
    """One line per container describing the identity surface actually present.

    Values are not logged — only the shape — so this stays safe to leave on.
    """
    global _context_logged
    if _context_logged or not LOG_REQUEST_CONTEXT:
        return
    _context_logged = True
    try:
        rc = event.get("requestContext")
        shape = {
            "event_keys": sorted(k for k in event if isinstance(k, str)),
            "requestContext_keys": sorted(rc) if isinstance(rc, dict) else None,
            "identity_keys": sorted(rc["identity"]) if isinstance(rc, dict)
                             and isinstance(rc.get("identity"), dict) else None,
            "principal_resolved": bool(_caller_principal(event)),
            # Header names only — the last place a caller identity could be.
            "header_keys": sorted(
                (((event.get("mcp") or {}).get("gatewayRequest") or {}).get("headers") or {})
            ) or None,
        }
        logger.info("Interceptor identity surface: %s", json.dumps(shape))
    except Exception as exc:
        logger.warning("Could not describe request context: %s", exc)


def _resolve_gateway_identity(headers: Dict[str, str]) -> Dict[str, str]:
    """Which gateway this call came through, from the Host header.

    Name resolution is derived from the ID rather than looked up, so a gateway
    that has never been seen before is still named correctly and no per-gateway
    configuration is needed.
    """
    host = ""
    for key, value in (headers or {}).items():
        if isinstance(key, str) and key.lower() == "host":
            host = str(value).split(":")[0]
            break
    gateway_id, confidence = extract_gateway_id_from_host(host)
    return {"host": host, "gateway_id": gateway_id,
            "gateway_name": derive_gateway_name(gateway_id) if gateway_id else "",
            "confidence": confidence}


# AgentCore rejects custom headers beginning with X-Amzn- except this one
# family, which is therefore the only supported way for a calling agent to
# identify itself to an interceptor. A live probe confirmed the gateway supplies
# no caller identity of its own: the event carries only interceptorInputVersion
# and mcp, with no requestContext, and the forwarded headers name the gateway
# (Host) and the transport, never the caller.
_CUSTOM_AGENT_HEADERS = (
    "x-amzn-bedrock-agentcore-runtime-custom-agent-name",
    "x-amzn-bedrock-agentcore-runtime-custom-agent-id",
    "x-amzn-bedrock-agentcore-runtime-custom-bot-name",
)

# HTTP-family runtime targets:
#   /{prefix}/runtimes/arn:...:runtime/{runtimeId}/invocations
_RUNTIME_INVOCATION_PATH = re.compile(r":runtime/([^/]+)/invocations", re.IGNORECASE)


def _caller_from_headers(headers: Dict[str, str]) -> str:
    """Agent name a caller declared about itself, or "" if it declared none."""
    for key, value in (headers or {}).items():
        if isinstance(key, str) and key.lower() in _CUSTOM_AGENT_HEADERS:
            text = str(value).strip()
            if text:
                return text
    return ""


def _resolve_caller_agent(headers: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """The AgentCore agent behind this call, when the principal names one.

    This is what makes bot-name the *agent* rather than the gateway: one gateway
    serves several agents, so only the per-request principal can tell them apart.
    """
    principal = _INVOCATION.get("principal", "")
    if not principal:
        # No principal from the event, so fall back to what the caller declared.
        # A self-declared name is weaker evidence than an AWS-supplied principal,
        # so it is only consulted once the stronger source has come up empty.
        declared = _caller_from_headers(headers or {})
        if declared:
            resolved = agent_for_role(declared) or None
            out = {"agent-name": declared, "agent-name-source": "caller-declared"}
            if resolved:
                out["agent-type"] = resolved.get("type", "")
                out["agent-role-arn"] = resolved.get("role_arn", "")
            return out
        return {}
    role = role_name_from_principal(principal)
    if not role:
        return {"caller-principal": principal}
    resolved = agent_for_role(role)
    out = {"caller-principal": principal, "caller-role": role}
    if resolved:
        out["agent-name"] = resolved.get("name", "")
        out["agent-type"] = resolved.get("type", "")
        out["agent-role-arn"] = resolved.get("role_arn", "")
    return out


def _agent_role_profile(caller: Dict[str, str]) -> Dict[str, str]:
    """Permissions of the *calling agent's* execution role.

    Emitted under the `harness-` names the discovery pipeline in
    akto_aws_bedrock_discovery already uses (harness-execution-role,
    harness-role-policies, ...), so a downstream reader sees one field set
    whether the record came from discovery or from this interceptor. The prefix
    is kept even when the caller is a Runtime rather than a Harness: matching
    the existing contract matters more here than the resource's own noun.
    """
    role_arn = caller.get("agent-role-arn") or ""
    if not role_arn:
        return {}
    try:
        profile = dict(get_role_security_profile(role_arn, "harness"))
        profile["harness-execution-role-arn"] = role_arn
        profile["harness-execution-role"] = role_arn.split("/")[-1]
        return profile
    except Exception as exc:
        logger.warning("Agent role profile failed for %s: %s", role_arn, exc)
        return {}


def _gateway_role_profile(gateway_id: str) -> Dict[str, str]:
    """Permissions of the gateway's own execution role — the identity it uses to
    reach the MCP backends behind it.

    Never blocks the call: the lookups are cached with a TTL, and any failure
    (no permission, throttling, a cold cache) yields no tags rather than delay.
    """
    if not gateway_id:
        return {}
    try:
        role_arn = gateway_role_arn(gateway_id)
        if not role_arn:
            return {}
        profile = dict(get_role_security_profile(role_arn, "gateway"))
        profile["gateway-execution-role-arn"] = role_arn
        # Two fields carry the harness- names the downstream reader consumes.
        # The gateway role has no attached managed policies — everything it can
        # do is inline — so the inline list is what belongs in the policies
        # field, not the empty attached one.
        profile["harness-execution-role"] = role_arn.split("/")[-1]
        profile["harness-role-policies"] = profile.pop("gateway-role-inline-policies", "")
        profile.pop("gateway-role-policies", None)
        return profile
    except Exception as exc:
        logger.warning("Gateway role profile failed for %s: %s", gateway_id, exc)
        return {}


def _build_tags(is_mcp: bool, identity: Optional[Dict[str, str]] = None,
                caller: Optional[Dict[str, str]] = None,
                agent_profile: Optional[Dict[str, str]] = None,
                gateway_profile: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """Tags for one intercepted call.

    MCP traffic is tagged as an MCP server/client and everything else (LLM /
    AI-agent calls) as gen-ai, as before. The identity half mirrors what the
    discovery pipeline puts on a gateway's discovery message, so the discovered
    gateway and its live traffic are recognisably the same thing.

    bot-name prefers the *calling agent* over the gateway: a gateway serves many
    agents, and naming the gateway on every call would collapse them into one.
    It falls back to the gateway only when the caller cannot be attributed.
    """
    identity = identity or {}
    caller = caller or {}
    kind = {"mcp-server": "MCP Server"} if is_mcp else {"gen-ai": "Gen AI"}
    tags = {
        "source": AKTO_SOURCE,
        **kind,
        "service": AKTO_CONNECTOR,
        "agentType": caller.get("agent-type") or AGENT_TYPE,
        # The Host header verbatim. AKTO groups traffic into collections by host,
        # so naming the graph node the same thing keeps the node and the
        # collection describing one object instead of two. The derived short
        # name is still available separately as gateway-name.
        "bot-name": caller.get("agent-name") or identity.get("host") or identity.get("gateway_id", ""),
        "agent-name": caller.get("agent-name", ""),
        # Provenance matters: a name the caller declared about itself is weaker
        # evidence than one AWS supplied, and a reader should be able to tell.
        "agent-name-source": caller.get("agent-name-source", ""),
        "caller-role": caller.get("caller-role", ""),
        "caller-principal": caller.get("caller-principal", ""),
        "gateway-id": identity.get("gateway_id", ""),
        "gateway-name": identity.get("gateway_name", ""),
        "account-id": _INVOCATION.get("account_id", ""),
        "region": AWS_REGION,
        # Both profiles use the harness- names, so ordering is the precedence
        # rule: the gateway's role is the fallback, and the calling agent's own
        # role overwrites it whenever it could be resolved.
        **(gateway_profile or {}),
        **(agent_profile or {}),
    }
    # An empty value is worse than an absent key: it looks like a real answer.
    return {k: v for k, v in tags.items() if v not in ("", None)}


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


def _build_trace_data(request_payload: str) -> Dict[str, Any]:
    """toolsSummary for the tool this request is calling.

    The runtime's graph builder reads traceData.toolsSummary.tools to draw the
    agent -> tool edges. An interceptor sees exactly one tool call per request,
    so the summary is that one tool with a count of one — accurate rather than
    aggregated, and the graph merges repeats across requests itself.
    """
    try:
        body = json.loads(request_payload) if request_payload else {}
    except (TypeError, ValueError):
        return {"toolsSummary": {}}
    if not isinstance(body, dict) or body.get("method") != "tools/call":
        return {"toolsSummary": {}}
    name = ((body.get("params") or {}).get("name") or "").strip()
    if not name:
        return {"toolsSummary": {}}
    return {"toolsSummary": {"tools": [name], "totalToolCalls": 1}}


def _build_aws_metadata(tags: Dict[str, str], request_payload: str = "") -> Dict[str, Any]:
    """The role/permission subset of the tags, plus what the graph builder needs.

    Mirrors traceDiscovery.js: `tag` is a JSON string a consumer has to parse
    separately, so anything needed to answer "what could this agent do" is also
    placed in the message body. Deliberately a subset — identity tags such as
    bot-name and region live in `tag`, exactly as they do on the discovery side.

    `model` and `traceData` are required by BedrockAgentTraceParser's validity
    check; without both, canParse() rejects the record and no trace, spans or
    service graph are produced at all. `model` is deliberately empty: a gateway
    interceptor sees MCP tool traffic and never a model call, so there is no
    honest value, and inventing one would put a node in the service graph that
    corresponds to nothing.
    """
    keep = ("-role-", "-execution-role", "-permissions-boundary")
    metadata: Dict[str, Any] = {k: v for k, v in tags.items() if any(m in k for m in keep)}
    metadata["model"] = ""
    metadata["traceData"] = _build_trace_data(request_payload)
    return metadata


def _embed_aws_metadata(response_payload: str, aws_metadata: Dict[str, str]) -> str:
    """Attach awsMetadata to the response body, the way the discovery pipeline does.

    The body here is the real MCP response rather than a synthesised one, so it
    is only extended when it is a JSON object and there is something to add —
    a non-object body (or an empty profile) is passed through untouched rather
    than reshaped into something the caller never sent.
    """
    if not aws_metadata:
        return response_payload
    try:
        parsed = json.loads(response_payload) if response_payload else {}
    except (TypeError, ValueError):
        return response_payload
    if not isinstance(parsed, dict):
        return response_payload
    parsed["awsMetadata"] = aws_metadata
    return json.dumps(parsed)


def _build_ingest_payload(*, request_payload: str, response_payload: str,
                          request_headers: Dict[str, str], response_headers: Dict[str, str],
                          status_code: Optional[int], is_mcp: bool,
                          path: str = "/mcp", method: str = "POST") -> Dict[str, Any]:
    """HTTP-proxy IngestDataBatch shape expected by the guardrails service
    (models.IngestDataBatch). Carries the real gateway headers/status, not
    synthesised values."""
    # Resolve before _ensure_host, so the gateway comes from its real Host header
    # rather than the synthetic fallback that replaces a missing one.
    identity = _resolve_gateway_identity(request_headers)
    caller = _resolve_caller_agent(request_headers)
    agent_profile = _agent_role_profile(caller)
    gateway_profile = _gateway_role_profile(identity.get("gateway_id", ""))
    tags = _build_tags(is_mcp, identity, caller, agent_profile, gateway_profile)
    if not caller.get("agent-name"):
        match = _RUNTIME_INVOCATION_PATH.search(path)
        if match:
            tags["bot-name"] = derive_gateway_name(match.group(1))
    # Request phase has no response yet -> default to 200/OK; response phase
    # carries the real gateway status. statusCode is numeric; status is the
    # HTTP reason phrase ("OK", "Not Found", ...).
    code = status_code if status_code is not None else 200
    request_headers = _ensure_host(request_headers, is_mcp)
    # awsMetadata travels INSIDE responsePayload, not as a top-level field.
    # AKTO's ingest schema is fixed, so an unrecognised top-level key is dropped
    # server-side and never reaches the reader — which is exactly how the
    # discovery pipeline does it (traceMessageBuilder.js builds
    # responsePayload = {response, awsMetadata}).
    aws_metadata = _build_aws_metadata(tags, request_payload)
    response_payload = _embed_aws_metadata(response_payload, aws_metadata)

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
        _log_payload(guardrails_url, payload)
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
        _log_payload(guardrails_url, payload)
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
        _log_payload(guardrails_url, payload)
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
        _log_payload(guardrails_url, payload)
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
        _INVOCATION["principal"] = _caller_principal(event)
        _INVOCATION["account_id"] = account_id_from_context(context)
        _log_request_context_once(event)

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
