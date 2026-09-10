"""Gateway identity derivation from a request's Host header.

Deliberately dependency-free — no boto3, no config — because the interceptor
imports it on the hot path. It is also a direct port of gatewayNaming.js in the
akto_aws_bedrock_discovery repo, and must stay a direct port: if discovery and
live traffic derived gateway names differently, the gateway AKTO discovered and
the traffic flowing through it would disagree on `bot-name` and land in the
dashboard as two unrelated things.
"""
import re

# AgentCore gateway IDs are "<name>-<10 char suffix>", e.g.
#   akto-unified-test-gateway-1-ur3v24waoj -> akto-unified-test-gateway-1
_ID_SUFFIX = re.compile(r"-[a-z0-9]{10}$", re.IGNORECASE)

# The synthetic host used when a gateway sends no Host header. Never a real
# gateway, so it must not be mistaken for one.
SYNTHETIC_HOST_LABEL = "agentcore_gateway"

_STRICT_HOST = re.compile(r"^([^.]+)\.gateway\.bedrock-agentcore\.", re.IGNORECASE)
_IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_ALL_DIGITS = re.compile(r"^\d+$")


def derive_gateway_name(gateway_id: str) -> str:
    """Best-effort gateway name from its ID.

    This is what lets a published name map carry only exceptions rather than one
    entry per gateway. Returns the ID unchanged when it does not look like
    name+suffix, which is the safe direction: a slightly odd bot-name beats a
    wrong one.
    """
    if not gateway_id:
        return ""
    stripped = _ID_SUFFIX.sub("", str(gateway_id))
    # Refuse to strip everything (an ID that is *only* a suffix) or to return
    # something implausibly short.
    return stripped if stripped and len(stripped) >= 3 else str(gateway_id)


def extract_gateway_id_from_host(host: str):
    """Gateway ID from a Host header, as (gateway_id, confidence).

    AgentCore hosts look like
      <gatewayId>.gateway.bedrock-agentcore.<region>.amazonaws.com

    Two tiers on purpose. The strict form requires AWS's documented middle
    segment, so nothing unrelated is ever mistaken for a gateway. The lenient
    fallback takes the first DNS label when the strict form fails, which keeps
    identity working if AWS changes its hostname format instead of silently
    losing it forever.
    """
    bare = str(host or "").split(":")[0].strip()
    if not bare:
        return "", "none"

    strict = _STRICT_HOST.match(bare)
    if strict:
        return strict.group(1), "strict"

    first_label = bare.split(".")[0]
    if not first_label or first_label.lower() == SYNTHETIC_HOST_LABEL:
        return "", "none"
    # A single-label host (localhost) isn't a gateway hostname.
    if "." not in bare:
        return "", "none"
    # Nor is an IP address — its first octet is not a gateway ID.
    if _IPV4.match(bare):
        return "", "none"
    # Gateway IDs are DNS-ish; a purely numeric label is something else.
    if _ALL_DIGITS.match(first_label):
        return "", "none"

    return first_label, "lenient"
