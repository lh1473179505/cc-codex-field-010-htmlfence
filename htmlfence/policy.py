"""Sanitizer policy loader."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


class PolicyError(ValueError):
    pass


@dataclass
class Policy:
    allowed_tags: set[str]
    allowed_attrs: set[str]
    url_attrs: set[str]
    allowed_url_schemes: set[str]
    drop_comments: bool
    raw: dict[str, Any] = field(default_factory=dict)


def load_policy(path: str | Path) -> Policy:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception as exc:
        raise PolicyError(f"failed to read policy: {exc}") from exc
    if not isinstance(data, dict):
        raise PolicyError("policy must be a JSON object")

    def _strset(name: str, default: list[str] | None = None) -> set[str]:
        val = data.get(name, default if default is not None else [])
        if not isinstance(val, list) or not all(isinstance(x, str) for x in val):
            raise PolicyError(f"{name} must be an array of strings")
        return {x.lower() for x in val}

    return Policy(
        allowed_tags=_strset("allowed_tags"),
        allowed_attrs=_strset("allowed_attrs"),
        url_attrs=_strset("url_attrs", ["href", "src", "cite", "action", "formaction", "xlink:href"]),
        allowed_url_schemes=_strset("allowed_url_schemes", ["http", "https", "mailto"]),
        drop_comments=bool(data.get("drop_comments", True)),
        raw=data,
    )
