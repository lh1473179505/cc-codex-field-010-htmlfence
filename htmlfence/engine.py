"""HTML sanitizer engine. Not implemented in this snapshot."""

from __future__ import annotations

from typing import Any

from htmlfence.policy import Policy
from htmlfence.tokens import Token


def sanitize_tokens(tokens: list[Token], policy: Policy) -> tuple[str, dict[str, Any]]:
    raise NotImplementedError("sanitize_tokens is not implemented in this snapshot")
