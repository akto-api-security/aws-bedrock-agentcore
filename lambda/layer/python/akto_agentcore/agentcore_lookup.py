"""Resolves who is on each side of an intercepted gateway call.

Two questions this answers, both needing AWS control-plane reads the request
itself cannot supply:

  * which gateway was called   -> its execution role, for the IAM profile
  * which agent called it      -> bot-name

The second matters because a gateway is one-to-many: AKTO's own demo gateway is
used by both a Runtime (asl_demo_agent_demo, via its GATEWAY_URL env var) and a
Harness (harness_khsh4, via its tools config). A static gateway->agent map would
mislabel one of them, so attribution has to come from the calling principal on
each request.

Everything is cached per container with a TTL and fails open: a lookup that
cannot be made costs a tag, never the tool call.
"""
import logging
import os
import re
import time
from typing import Dict, Optional, Tuple

logger = logging.getLogger(__name__)

LOOKUP_TTL_SECONDS = float(os.getenv("AKTO_LOOKUP_TTL_SECONDS", "900"))

_cache: Dict[str, dict] = {}

# arn:aws:sts::123456789012:assumed-role/<role>/<session>
_ASSUMED_ROLE = re.compile(r"^arn:aws[^:]*:sts::\d{12}:assumed-role/([^/]+)/(.*)$")
# arn:aws:iam::123456789012:role/<path>/<role>
_IAM_ROLE = re.compile(r"^arn:aws[^:]*:iam::\d{12}:role/(?:.*/)?([^/]+)$")
_LAMBDA_ARN_ACCOUNT = re.compile(r"^arn:aws[^:]*:lambda:[^:]+:(\d{12}):")


def _client(service: str):
    """boto3 comes from the Lambda runtime, not the layer. Imported lazily so
    this module (and the unit tests) load without it.

    The region is passed explicitly rather than left to boto3's own resolution:
    a developer's ~/.aws/config default would otherwise silently point these
    lookups at the wrong region and return a different account's resources.
    """
    import boto3  # noqa: PLC0415
    region = os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION") or None
    return boto3.client(service, region_name=region) if region else boto3.client(service)


def _cache_get(key: str):
    entry = _cache.get(key)
    if not entry:
        return None
    if time.time() - entry["at"] > LOOKUP_TTL_SECONDS:
        _cache.pop(key, None)
        return None
    return entry["value"]


def _cache_set(key: str, value):
    _cache[key] = {"at": time.time(), "value": value}
    return value


def account_id_from_context(context) -> str:
    """Account ID from the Lambda context ARN.

    Preferred over an environment variable: Lambda does not set one, and the
    deploy script would otherwise need a new required input just to tag traffic.
    """
    arn = getattr(context, "invoked_function_arn", "") or ""
    match = _LAMBDA_ARN_ACCOUNT.match(arn)
    if match:
        return match.group(1)
    return os.getenv("AWS_ACCOUNT_ID", "")


def role_name_from_principal(principal: str) -> str:
    """Role name out of whatever identity string the gateway supplies.

    Accepts an assumed-role STS ARN, a plain IAM role ARN, or a bare role name.
    Returns "" for anything else (an IAM user, a federated identity, a JWT
    subject) rather than guessing.
    """
    value = str(principal or "").strip()
    if not value:
        return ""
    match = _ASSUMED_ROLE.match(value)
    if match:
        return match.group(1)
    match = _IAM_ROLE.match(value)
    if match:
        return match.group(1)
    # A bare role name has no ARN punctuation; anything with a colon is an ARN
    # shape we deliberately do not recognise.
    return value if ":" not in value and "/" not in value else ""


def gateway_role_arn(gateway_id: str) -> str:
    """Execution role of a gateway — the identity it uses to reach its targets."""
    if not gateway_id:
        return ""
    key = f"gw-role:{gateway_id}"
    cached = _cache_get(key)
    if cached is not None:
        return cached
    try:
        detail = _client("bedrock-agentcore-control").get_gateway(gatewayIdentifier=gateway_id)
        return _cache_set(key, detail.get("roleArn", "") or "")
    except Exception as exc:
        logger.warning("GetGateway failed for %s: %s", gateway_id, exc)
        return _cache_set(key, "")


def _build_role_to_agent_map() -> Dict[str, Dict[str, str]]:
    """role name -> {name, type, role_arn} for every AgentCore agent.

    The role ARN is kept because reconstructing it from the name would drop the
    IAM path (/service-role/), and a wrong ARN reads IAM for the wrong role.

    Harnesses are folded in after runtimes on purpose: a Harness and its
    auto-provisioned Runtime commonly share one execution role, and the Harness
    is the resource a human recognises.
    """
    mapping: Dict[str, Dict[str, str]] = {}
    try:
        control = _client("bedrock-agentcore-control")
    except Exception as exc:
        logger.warning("boto3 unavailable — agent attribution disabled: %s", exc)
        return mapping

    try:
        for runtime in control.list_agent_runtimes().get("agentRuntimes", []) or []:
            rid = runtime.get("agentRuntimeId")
            if not rid:
                continue
            try:
                detail = control.get_agent_runtime(agentRuntimeId=rid)
                role_arn = detail.get("roleArn", "") or ""
                role = role_name_from_principal(role_arn)
                if role:
                    mapping[role] = {"name": detail.get("agentRuntimeName") or rid,
                                     "type": "RUNTIME", "role_arn": role_arn}
            except Exception as exc:
                logger.warning("GetAgentRuntime failed for %s: %s", rid, exc)
    except Exception as exc:
        logger.warning("ListAgentRuntimes failed: %s", exc)

    try:
        for harness in control.list_harnesses().get("harnesses", []) or []:
            hid = harness.get("harnessId")
            if not hid:
                continue
            try:
                detail = (control.get_harness(harnessId=hid) or {}).get("harness", {})
                role_arn = detail.get("executionRoleArn", "") or ""
                role = role_name_from_principal(role_arn)
                if role:
                    mapping[role] = {"name": detail.get("harnessName") or hid,
                                     "type": "HARNESS", "role_arn": role_arn}
            except Exception as exc:
                logger.warning("GetHarness failed for %s: %s", hid, exc)
    except Exception as exc:
        logger.warning("ListHarnesses failed: %s", exc)

    return mapping


def agent_for_role(role_name: str) -> Optional[Dict[str, str]]:
    """{name, type, role_arn} for a calling role, or None when no agent owns it.

    None is a real answer, not a failure: a human or an application calling the
    gateway directly is not an AgentCore agent and must not be labelled as one.
    """
    if not role_name:
        return None
    cached = _cache_get("role-map")
    if cached is None:
        cached = _cache_set("role-map", _build_role_to_agent_map())
    return cached.get(role_name)
