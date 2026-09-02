"""Composition support for adding Akto to an existing AgentCore interceptor."""

from copy import deepcopy
from functools import wraps
from typing import Any, Callable, Dict

from .core import lambda_handler as akto_lambda_handler

Handler = Callable[[Dict[str, Any], Any], Dict[str, Any]]
_PROTOCOLS = ("mcp", "http")


def _protocol(event: Dict[str, Any]) -> str:
    for name in _PROTOCOLS:
        if isinstance(event.get(name), dict):
            return name
    raise ValueError("AgentCore interceptor event must contain 'mcp' or 'http'")


def _is_response(event: Dict[str, Any], protocol: str) -> bool:
    return event[protocol].get("gatewayResponse") is not None


def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    merged = deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = deepcopy(value)
    return merged


def _validate_output(output: Any, protocol: str) -> Dict[str, Any]:
    if not isinstance(output, dict):
        raise TypeError("Existing interceptor must return a dictionary")
    if output.get("interceptorOutputVersion") != "1.0":
        raise ValueError("Existing interceptor must return interceptorOutputVersion='1.0'")
    if not isinstance(output.get(protocol), dict):
        raise ValueError(f"Existing interceptor output must contain '{protocol}'")
    return output


def _effective_event(
    event: Dict[str, Any], output: Dict[str, Any], protocol: str
) -> Dict[str, Any]:
    """Apply the existing interceptor's transform to a copy of AWS's event."""
    effective = deepcopy(event)
    protocol_output = output[protocol]
    response_phase = _is_response(event, protocol)

    if response_phase:
        transformed = protocol_output.get("transformedGatewayResponse")
        if isinstance(transformed, dict):
            current = effective[protocol].get("gatewayResponse") or {}
            effective[protocol]["gatewayResponse"] = _deep_merge(current, transformed)
        return effective

    transformed_response = protocol_output.get("transformedGatewayResponse")
    if isinstance(transformed_response, dict):
        # A REQUEST interceptor may short-circuit the target. Treat that
        # synthetic response as the final response and scan it before return.
        effective[protocol]["gatewayResponse"] = deepcopy(transformed_response)
        return effective

    transformed_request = protocol_output.get("transformedGatewayRequest")
    if isinstance(transformed_request, dict):
        current = effective[protocol].get("gatewayRequest") or {}
        effective[protocol]["gatewayRequest"] = _deep_merge(current, transformed_request)
    return effective


def _merge_outputs(
    existing: Dict[str, Any], akto: Dict[str, Any], protocol: str
) -> Dict[str, Any]:
    """Retain customer transforms while giving Akto's final decision precedence."""
    existing_protocol = existing[protocol]
    akto_protocol = akto.get(protocol)
    if not isinstance(akto_protocol, dict):
        raise ValueError(f"Akto interceptor output must contain '{protocol}'")
    if not akto_protocol:
        return existing

    return {
        "interceptorOutputVersion": "1.0",
        protocol: _deep_merge(existing_protocol, akto_protocol),
    }


def wrap_interceptor(handler: Handler) -> Handler:
    """Wrap an existing AgentCore interceptor with final Akto enforcement.

    The existing interceptor runs first. Akto then scans the effective payload,
    including any customer transformation, so later code cannot bypass an Akto
    block or rewrite. Existing headers and other unrelated fields are retained.
    """
    if not callable(handler):
        raise TypeError("handler must be callable")

    @wraps(handler)
    def wrapped(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
        protocol = _protocol(event)
        existing_output = _validate_output(handler(event, context), protocol)
        effective = _effective_event(event, existing_output, protocol)
        akto_output = akto_lambda_handler(effective, context)
        return _merge_outputs(existing_output, akto_output, protocol)

    return wrapped
