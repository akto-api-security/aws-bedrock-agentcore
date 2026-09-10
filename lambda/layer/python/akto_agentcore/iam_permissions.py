"""Turns an execution role into a flat set of security tags.

Port of iamPermissions.js from the akto_aws_bedrock_discovery repo, kept
field-for-field identical so a gateway described by this interceptor and a
harness described by the discovery Lambda can be read the same way.

The role name and its attached policy *names* say which policies exist; they
never say what the caller may actually do. Answering "can this reach secrets /
assume another role / touch any bucket" needs the policy documents themselves,
the inline policies the attached list omits, the trust policy (who may assume
the role at all) and the permissions boundary (the ceiling on everything else).

Fail-open throughout: a role that cannot be read yields fewer tags, never a
failed request. This module sits behind a synchronous guardrail — losing
enrichment must never cost the caller its tool call.
"""
import json
import logging
import os
import re
import time
import urllib.parse
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)

# Tags ride on every intercepted call, so an IAM-heavy role must not dominate
# the payload. Actions get the larger budget because they are the field a
# reviewer actually reads.
MAX_ACTIONS_CHARS = 1500
MAX_FIELD_CHARS = 512

# Lambda keeps module state for a container's whole life, so an unbounded cache
# would serve a role's permissions from the moment the container started — hours
# after a policy changed. A TTL bounds that staleness while still collapsing
# thousands of calls onto one set of IAM reads.
PROFILE_TTL_SECONDS = float(os.getenv("AKTO_IAM_PROFILE_TTL_SECONDS", "900"))

# Actions worth surfacing on their own rather than leaving buried in the full
# list: privilege escalation, credential access, and broad data reach.
_PRIVILEGED_PATTERNS = [re.compile(p, re.IGNORECASE) for p in (
    r"^iam:", r"^sts:AssumeRole", r"^organizations:",
    r"^secretsmanager:Get", r"^secretsmanager:List", r"^ssm:GetParameter",
    r"^kms:Decrypt", r"^kms:GenerateDataKey",
    r"^s3:GetObject", r"^s3:PutObject", r"^s3:DeleteObject",
    r"^lambda:InvokeFunction", r"^lambda:UpdateFunctionCode", r"^lambda:AddPermission",
    r"^dynamodb:(Get|Put|Delete|Scan|Query)",
    r"^ec2:RunInstances", r"^ec2:CreateTags",
    r"^bedrock:InvokeModel", r"^bedrock-agentcore:Invoke",
)]

_ROLE_ACCOUNT = re.compile(r"^arn:aws[^:]*:iam::(\d{12}):")
_EXTERNAL_PRINCIPAL = re.compile(r"^arn:aws[^:]*:(?:iam|sts)::(\d{12}):")

_cache: Dict[str, Any] = {}


def _iam_client():
    """boto3 is provided by the Lambda runtime, not vendored into the layer.
    Imported lazily so the module (and the unit tests) load without it.

    IAM is global, but the region still selects the endpoint; passing it
    explicitly keeps this consistent with the other lookups.
    """
    import boto3  # noqa: PLC0415
    region = os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION") or None
    return boto3.client("iam", region_name=region) if region else boto3.client("iam")


def _cache_get(key: str):
    entry = _cache.get(key)
    if not entry:
        return None
    if time.time() - entry["at"] > PROFILE_TTL_SECONDS:
        _cache.pop(key, None)
        return None
    return entry["value"]


def _cache_set(key: str, value):
    _cache[key] = {"at": time.time(), "value": value}
    return value


def _parse_policy_document(doc: Any) -> Optional[dict]:
    """IAM returns policy documents URL-encoded in some paths and pre-parsed in
    others, depending on SDK version. Accept every shape rather than assume one."""
    if not doc:
        return None
    if isinstance(doc, dict):
        return doc
    try:
        return json.loads(doc)
    except (TypeError, ValueError):
        pass
    try:
        return json.loads(urllib.parse.unquote(doc))
    except (TypeError, ValueError):
        return None


def _as_list(value) -> list:
    """IAM allows a bare string or an array everywhere a list is accepted."""
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _join_capped(values, max_chars: int) -> str:
    """Joins into a bounded, comma-separated tag value."""
    items = sorted(values)
    out: List[str] = []
    used = 0
    for i, item in enumerate(items):
        cost = len(item) + (1 if out else 0)
        if used + cost > max_chars:
            return ",".join(out) + f",…+{len(items) - i} more"
        out.append(item)
        used += cost
    return ",".join(out)


class _Acc:
    def __init__(self):
        self.actions: Set[str] = set()
        self.deny_actions: Set[str] = set()
        self.services: Set[str] = set()
        self.resources: Set[str] = set()
        self.wildcard_actions: Set[str] = set()
        self.wildcard_resource_actions: Set[str] = set()
        self.privileged_actions: Set[str] = set()
        self.trust_principals: Set[str] = set()
        self.trust_conditions: Set[str] = set()
        self.trust_external_accounts: Set[str] = set()
        self.is_admin = False
        self.trust_wildcard = False
        self.statement_count = 0


def _absorb_statements(document: Optional[dict], acc: _Acc) -> None:
    for statement in _as_list((document or {}).get("Statement")):
        if not isinstance(statement, dict):
            continue
        acc.statement_count += 1
        actions = [a for a in (_as_list(statement.get("Action")) + _as_list(statement.get("NotAction")))
                   if isinstance(a, str)]
        resources = [r for r in _as_list(statement.get("Resource")) if isinstance(r, str)]
        for resource in resources:
            acc.resources.add(resource)
        is_deny = statement.get("Effect") == "Deny"
        resource_is_wildcard = any(r == "*" for r in resources)

        for action in actions:
            if is_deny:
                acc.deny_actions.add(action)
                continue
            acc.actions.add(action)
            service = action.split(":")[0] if ":" in action else action
            if service and service != "*":
                acc.services.add(service)
            if "*" in action:
                acc.wildcard_actions.add(action)
            if resource_is_wildcard:
                acc.wildcard_resource_actions.add(action)
            if any(p.match(action) for p in _PRIVILEGED_PATTERNS):
                acc.privileged_actions.add(action)
            if action == "*" and resource_is_wildcard:
                acc.is_admin = True


def _read_trust_policy(document: Optional[dict], acc: _Acc, account_id: str) -> None:
    """Who may assume the role, under which condition keys."""
    for statement in _as_list((document or {}).get("Statement")):
        if not isinstance(statement, dict) or statement.get("Effect") != "Allow":
            continue
        principal = statement.get("Principal")
        entries: List[str] = []
        if isinstance(principal, str):
            entries.append(principal)
        elif isinstance(principal, dict):
            for value in principal.values():
                entries.extend(str(e) for e in _as_list(value))
        for entry in entries:
            acc.trust_principals.add(entry)
            # A bare "*" principal means anyone may assume the role — the single
            # most serious thing a trust policy can say.
            if entry == "*":
                acc.trust_wildcard = True
            match = _EXTERNAL_PRINCIPAL.match(entry)
            if match and match.group(1) != account_id:
                acc.trust_external_accounts.add(match.group(1))
        for operator in (statement.get("Condition") or {}).values():
            if isinstance(operator, dict):
                for key in operator:
                    acc.trust_conditions.add(key)


def get_role_security_profile(execution_role_arn: str, prefix: str) -> Dict[str, str]:
    """Security tag set for one execution role, keyed under `prefix`.

    Cached per role for PROFILE_TTL_SECONDS: a busy gateway resolves the same
    role on every call, and IAM is rate-limited.
    """
    if not execution_role_arn:
        return {}
    role_name = str(execution_role_arn).split("/")[-1]
    if not role_name:
        return {}

    cache_key = f"{prefix}:{role_name}"
    cached = _cache_get(cache_key)
    if cached is not None:
        return cached

    account_match = _ROLE_ACCOUNT.match(str(execution_role_arn))
    role_account_id = account_match.group(1) if account_match else ""

    acc = _Acc()
    attached_names: List[str] = []
    attached_arns: List[str] = []
    inline_names: List[str] = []
    policy_versions: List[str] = []
    policy_types: List[str] = []
    permissions_boundary = ""
    last_used = ""
    role_path = ""

    try:
        iam = _iam_client()
    except Exception as exc:
        logger.warning("boto3/IAM unavailable — role profile skipped: %s", exc)
        return {}

    # Trust policy, boundary, path and last-used all come from the one GetRole call.
    try:
        role = iam.get_role(RoleName=role_name).get("Role", {})
        _read_trust_policy(_parse_policy_document(role.get("AssumeRolePolicyDocument")), acc, role_account_id)
        permissions_boundary = (role.get("PermissionsBoundary") or {}).get("PermissionsBoundaryArn", "") or ""
        used = (role.get("RoleLastUsed") or {}).get("LastUsedDate")
        last_used = used.isoformat() if used else ""
        role_path = role.get("Path", "") or ""
    except Exception as exc:
        logger.warning("GetRole failed for %s: %s", role_name, exc)

    # Attached (managed) policies — the names were always reportable; the
    # documents behind them are what this adds.
    try:
        attached = iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", [])
        for policy in attached:
            name, arn = policy.get("PolicyName", ""), policy.get("PolicyArn", "")
            attached_names.append(name)
            attached_arns.append(arn)
            try:
                detail = iam.get_policy(PolicyArn=arn).get("Policy", {})
                version_id = detail.get("DefaultVersionId")
                updated = detail.get("UpdateDate")
                # Version + update date make a policy change detectable downstream
                # without diffing the whole document.
                policy_versions.append(
                    f"{name}:{version_id or '?'}@{updated.date().isoformat() if updated else '?'}")
                policy_types.append(
                    f"{name}:{'aws-managed' if str(arn).startswith('arn:aws:iam::aws:policy/') else 'customer-managed'}")
                if not version_id:
                    continue
                version = iam.get_policy_version(PolicyArn=arn, VersionId=version_id)
                _absorb_statements(_parse_policy_document((version.get("PolicyVersion") or {}).get("Document")), acc)
            except Exception as exc:
                logger.warning("Policy document read failed for %s: %s", arn, exc)
    except Exception as exc:
        logger.warning("ListAttachedRolePolicies failed for %s: %s", role_name, exc)

    # Inline policies are invisible to ListAttachedRolePolicies, so a role that
    # keeps its real grants inline looks unprivileged without this call. The
    # AgentCore gateway service role in AKTO's own account is exactly that case.
    try:
        for name in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            inline_names.append(name)
            try:
                inline = iam.get_role_policy(RoleName=role_name, PolicyName=name)
                _absorb_statements(_parse_policy_document(inline.get("PolicyDocument")), acc)
            except Exception as exc:
                logger.warning("GetRolePolicy failed for %s/%s: %s", role_name, name, exc)
    except Exception as exc:
        logger.warning("ListRolePolicies failed for %s: %s", role_name, exc)

    tags = {
        f"{prefix}-role-policies": _join_capped(attached_names, MAX_FIELD_CHARS),
        f"{prefix}-role-policy-arns": _join_capped(attached_arns, MAX_FIELD_CHARS),
        f"{prefix}-role-policy-versions": _join_capped(policy_versions, MAX_FIELD_CHARS),
        f"{prefix}-role-policy-types": _join_capped(policy_types, MAX_FIELD_CHARS),
        f"{prefix}-role-inline-policies": _join_capped(inline_names, MAX_FIELD_CHARS),
        f"{prefix}-role-services": _join_capped(acc.services, MAX_FIELD_CHARS),
        f"{prefix}-role-actions": _join_capped(acc.actions, MAX_ACTIONS_CHARS),
        f"{prefix}-role-resources": _join_capped(acc.resources, MAX_ACTIONS_CHARS),
        f"{prefix}-role-wildcard-actions": _join_capped(acc.wildcard_actions, MAX_FIELD_CHARS),
        f"{prefix}-role-wildcard-resource-actions": _join_capped(acc.wildcard_resource_actions, MAX_FIELD_CHARS),
        f"{prefix}-role-privileged-actions": _join_capped(acc.privileged_actions, MAX_FIELD_CHARS),
        f"{prefix}-role-deny-actions": _join_capped(acc.deny_actions, MAX_FIELD_CHARS),
        f"{prefix}-role-statement-count": str(acc.statement_count),
        f"{prefix}-role-is-admin": "true" if acc.is_admin else "false",
        f"{prefix}-role-path": role_path,
        f"{prefix}-role-is-service-linked": "true" if role_path.startswith("/aws-service-role/") else "false",
        f"{prefix}-role-trust-principals": _join_capped(acc.trust_principals, MAX_FIELD_CHARS),
        f"{prefix}-role-trust-conditions": _join_capped(acc.trust_conditions, MAX_FIELD_CHARS),
        f"{prefix}-role-trust-external-accounts": _join_capped(acc.trust_external_accounts, MAX_FIELD_CHARS),
        f"{prefix}-role-trust-wildcard-principal": "true" if acc.trust_wildcard else "false",
        f"{prefix}-permissions-boundary": permissions_boundary,
        f"{prefix}-role-last-used": last_used,
    }
    return _cache_set(cache_key, tags)
