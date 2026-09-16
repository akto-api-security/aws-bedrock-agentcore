"""The servers sitting behind an AgentCore Gateway.

A gateway is only a front door: every tool it exposes is actually served by a
*target*, and AWS models a target as one of several kinds — a remote MCP server,
a Lambda, an OpenAPI or Smithy description, an API Gateway, a pre-built
connector, or an AgentCore Runtime. Until this module existed the interceptor
knew none of them: a target survived only as the prefix inside a namespaced tool
name (`mac-akto-api-mcp___searchDocumentation`), with no endpoint, no auth
posture and no status.

Each kind names its backend differently, so normalisation picks a single
`host` per target that is meaningful to a human and stable across requests:
a real hostname where one exists, and the resource's own name where the backend
is an ARN and has no hostname at all.

Everything is cached per container with a TTL and fails open — a lookup that
cannot be made costs a tag, never the tool call.
"""
import logging
import os
import re
import time
import urllib.parse
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

TARGETS_TTL_SECONDS = float(os.getenv("AKTO_TARGETS_TTL_SECONDS", "900"))

# AgentCore namespaces a gateway's tools as "<targetName>___<toolName>".
TOOL_NAMESPACE_SEPARATOR = "___"

_cache: Dict[str, dict] = {}


def _client():
    """boto3 comes from the Lambda runtime, not the layer. Imported lazily so
    this module (and the unit tests) load without it. Region is passed
    explicitly: boto3's own resolution would otherwise fall back to a developer's
    ~/.aws/config default and silently read a different region's resources."""
    import boto3  # noqa: PLC0415
    region = os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION") or None
    return boto3.client("bedrock-agentcore-control", region_name=region) if region \
        else boto3.client("bedrock-agentcore-control")


def _cache_get(key: str):
    entry = _cache.get(key)
    if not entry:
        return None
    if time.time() - entry["at"] > TARGETS_TTL_SECONDS:
        _cache.pop(key, None)
        return None
    return entry["value"]


def _cache_set(key: str, value):
    _cache[key] = {"at": time.time(), "value": value}
    return value


# AgentCore appends a 10-character suffix to resource ids, exactly as it does
# for gateways. Stripping it keeps one runtime from appearing under two names:
# the runtime-path parser in core.py already derives the short form for the same
# traffic, and a record that disagreed with it would look like a second agent.
_ID_SUFFIX = re.compile(r"-[a-z0-9]{10}$", re.IGNORECASE)


def _name_from_arn(arn: str) -> str:
    """Resource name from an ARN, without AgentCore's generated id suffix."""
    tail = str(arn or "").split(":")[-1]
    # "runtime/asl_demo_agent_demo-wxoIOE9Fdr" -> "asl_demo_agent_demo-wxoIOE9Fdr"
    name = tail.split("/")[-1] if "/" in tail else tail
    stripped = _ID_SUFFIX.sub("", name)
    # Never strip down to something implausibly short; a slightly long name
    # beats an unrecognisable one.
    return stripped if len(stripped) >= 3 else name


def _host_from_url(url: str) -> str:
    try:
        return urllib.parse.urlparse(str(url or "")).hostname or ""
    except ValueError:
        return ""


def _describe_backend(config: Dict[str, Any], target_name: str):
    """(kind, backend, host) for whichever union variant the target uses.

    `backend` is the raw identifier AWS holds — a URL for network targets, an
    ARN for AWS-resource ones. `host` is what the record is grouped by, so it
    is a hostname when the backend has one and the resource's own name when it
    does not; falling back to the target name keeps a record attributable even
    for a variant this function has never seen.
    """
    mcp = (config or {}).get("mcp") or {}
    http = (config or {}).get("http") or {}

    server = mcp.get("mcpServer")
    if isinstance(server, dict):
        endpoint = server.get("endpoint", "")
        return "mcpServer", endpoint, _host_from_url(endpoint) or target_name

    for key in ("lambda", "connector", "apiGateway"):
        variant = mcp.get(key)
        if isinstance(variant, dict):
            arn = variant.get("arn") or variant.get("lambdaArn") or ""
            endpoint = variant.get("endpoint") or variant.get("uri") or ""
            host = _host_from_url(endpoint) or _name_from_arn(arn) or target_name
            return key, arn or endpoint, host

    for key in ("openApiSchema", "smithyModel"):
        variant = mcp.get(key)
        if isinstance(variant, dict):
            # Schema-described targets point at a document, not a live host.
            uri = ((variant.get("s3") or {}).get("uri")) or ""
            return key, uri or "inlinePayload", _host_from_url(uri) or target_name

    runtime = http.get("agentcoreRuntime")
    if isinstance(runtime, dict):
        arn = runtime.get("arn", "")
        # An AgentCore Runtime has no hostname; its own name is the only thing
        # that means anything to a reader, and it matches what the runtime-path
        # parser in core.py derives for the same traffic.
        return "agentcoreRuntime", arn, _name_from_arn(arn) or target_name

    for key, variant in list(http.items()):
        if isinstance(variant, dict):
            arn = variant.get("arn", "")
            endpoint = variant.get("endpoint") or variant.get("uri") or ""
            host = _host_from_url(endpoint) or _name_from_arn(arn) or target_name
            return key, arn or endpoint, host

    return "unknown", "", target_name


def _auth_of(detail: Dict[str, Any]) -> str:
    """Credential providers guarding the backend, or "none".

    "none" is a finding, not an absence of data: it means the gateway reaches
    that backend unauthenticated.
    """
    providers = detail.get("credentialProviderConfigurations") or []
    kinds = [p.get("credentialProviderType") for p in providers
             if isinstance(p, dict) and p.get("credentialProviderType")]
    return ",".join(kinds) if kinds else "none"


def _normalise(detail: Dict[str, Any], summary: Dict[str, Any]) -> Dict[str, str]:
    name = detail.get("name") or summary.get("name") or summary.get("targetId", "")
    kind, backend, host = _describe_backend(detail.get("targetConfiguration") or {}, name)
    listing = (((detail.get("targetConfiguration") or {}).get("mcp") or {})
               .get("mcpServer") or {}).get("listingMode", "")
    synced = detail.get("lastSynchronizedAt")
    return {
        "name": name,
        "target_id": detail.get("targetId") or summary.get("targetId", ""),
        "kind": kind,
        "backend": str(backend or ""),
        "host": host,
        "auth": _auth_of(detail),
        "status": str(detail.get("status") or summary.get("status") or ""),
        "listing_mode": str(listing or ""),
        "private": "true" if detail.get("privateEndpoint") else "false",
        "last_synchronized": synced.isoformat() if hasattr(synced, "isoformat") else "",
    }


def targets_for_gateway(gateway_id: str) -> List[Dict[str, str]]:
    """Every target behind a gateway, normalised. [] when it cannot be read."""
    if not gateway_id:
        return []
    cached = _cache_get(f"targets:{gateway_id}")
    if cached is not None:
        return cached

    targets: List[Dict[str, str]] = []
    try:
        control = _client()
    except Exception as exc:
        logger.warning("boto3 unavailable — target discovery disabled: %s", exc)
        return _cache_set(f"targets:{gateway_id}", targets)

    try:
        paginator_token = None
        summaries: List[Dict[str, Any]] = []
        while True:
            kwargs = {"gatewayIdentifier": gateway_id}
            if paginator_token:
                kwargs["nextToken"] = paginator_token
            page = control.list_gateway_targets(**kwargs)
            summaries.extend(page.get("items", []) or [])
            paginator_token = page.get("nextToken")
            if not paginator_token:
                break
    except Exception as exc:
        logger.warning("ListGatewayTargets failed for %s: %s", gateway_id, exc)
        return _cache_set(f"targets:{gateway_id}", targets)

    for summary in summaries:
        target_id = summary.get("targetId")
        if not target_id:
            continue
        try:
            detail = control.get_gateway_target(gatewayIdentifier=gateway_id, targetId=target_id)
            targets.append(_normalise(detail, summary))
        except Exception as exc:
            logger.warning("GetGatewayTarget failed for %s/%s: %s", gateway_id, target_id, exc)

    return _cache_set(f"targets:{gateway_id}", targets)


def target_name_from_tool(tool_name: str) -> str:
    """The target a namespaced tool belongs to, or "" for a bare tool name."""
    text = str(tool_name or "")
    if TOOL_NAMESPACE_SEPARATOR not in text:
        return ""
    return text.split(TOOL_NAMESPACE_SEPARATOR, 1)[0].strip()


def target_for_tool(gateway_id: str, tool_name: str) -> Optional[Dict[str, str]]:
    """The server behind a called tool, or None when it cannot be resolved."""
    name = target_name_from_tool(tool_name)
    if not name:
        return None
    for target in targets_for_gateway(gateway_id):
        if target.get("name") == name:
            return target
    return None
