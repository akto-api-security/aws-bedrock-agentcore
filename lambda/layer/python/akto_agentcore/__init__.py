"""Public API for the Akto Amazon Bedrock AgentCore Lambda layer."""

from .core import lambda_handler
from .wrapper import wrap_interceptor

__all__ = ["lambda_handler", "wrap_interceptor"]
