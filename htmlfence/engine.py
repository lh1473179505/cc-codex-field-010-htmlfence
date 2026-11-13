"""HTML sanitizer engine.

Walks the tokenizer's token stream, drops whatever the policy forbids, and
serializes a conservative, stable output document. The serialization is the
security contract: re-tokenizing the output must not yield forbidden tags,
event-handler attributes, or disallowed URL schemes, and re-sanitizing the
output must be a fixed point.
"""

from __future__ import annotations

import re
from typing import Any

from htmlfence.policy import Policy
from htmlfence.tokenize import tokenize
from htmlfence.tokens import (
    VOID_TAGS,
    Comment,
    Doctype,
    EndTag,
    StartTag,
    Text,
    Token,
)

# Elements whose contents are parsed in a context-dependent way (RAWTEXT,
# RCDATA, or foreign content). They are never emitted, even if a policy
# lists them, and they are dropped together with their contents.
NEVER_EMIT = frozenset({
    "script", "style", "iframe", "noembed", "noframes", "xmp", "noscript",
    "plaintext", "svg", "math", "template",
})

# When one of these tags is dropped, its contents are dropped too, up to the
# matching end tag (or the RAWTEXT/RCDATA closer the tokenizer consumed).
DROP_WITH_CONTENTS = frozenset({
    "script", "style", "iframe", "object", "embed", "link", "meta", "base",
    "form", "textarea", "title", "noscript", "noembed", "noframes", "xmp",
    "plaintext", "svg", "math", "template",
})

_ASCII_WS = " \t\n\r\f"
_ATTR_NAME_RE = re.compile(r"^[^\s/<>\"'=]+$")
_ID_RE = re.compile(r"^[A-Za-z0-9_-]*$")
_CLASS_RE = re.compile(r"^[A-Za-z0-9_\- ]*$")
_SCHEME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*$")


def _escape_text(data: str) -> str:
    return data.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _escape_attr(data: str) -> str:
    return _escape_text(data).replace('"', "&quot;")


def _valid_url(value: str, schemes: set[str]) -> bool:
    v = value.strip(_ASCII_WS)
    if v == "":
        return True
    # Control characters anywhere enable disguised schemes (java\tscript:).
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in v):
        return False
    # A backslash is a path separator to browsers; never allow it.
    if "\\" in v:
        return False
    # Scheme = alpha sequence before ':' that precedes any '/', '?', '#'.
    first = len(v)
    for sep in "/?#:":
        j = v.find(sep)
        if j != -1 and j < first:
            first = j
    if first < len(v) and v[first] == ":":
        candidate = v[:first]
        if not _SCHEME_RE.match(candidate):
            return False
        return candidate.lower() in schemes
    # Relative reference: no raw '<' allowed.
    return "<" not in v


def _filter_attrs(
    tag: str,
    attrs: list[tuple[str, str]],
    policy: Policy,
    schemes: set[str],
    dropped: list[dict[str, Any]],
) -> list[tuple[str, str]]:
    kept: list[tuple[str, str]] = []
    seen: set[str] = set()
    for name, value in attrs:
        reason: str | None = None
        if not name or not _ATTR_NAME_RE.match(name):
            reason = "dropped_attr"
        elif name.lower().startswith("on"):
            reason = "dropped_attr"
        elif name not in policy.allowed_attrs:
            reason = "dropped_attr"
        elif name in seen:
            reason = "dropped_attr"
        elif name == "id" and not _ID_RE.match(value):
            reason = "dropped_attr"
        elif name == "class" and not _CLASS_RE.match(value):
            reason = "dropped_attr"
        elif name in policy.url_attrs:
            value = value.strip(_ASCII_WS)
            if not _valid_url(value, schemes):
                reason = "dropped_url"
        if reason is not None:
            dropped.append({"kind": "attr", "name": name, "tag": tag, "reason": reason})
            continue
        seen.add(name)
        kept.append((name, value.replace("\x00", "")))
    return kept


def _clean(tokens: list[Token], policy: Policy) -> tuple[str, list[dict[str, Any]]]:
    allowed = {t for t in policy.allowed_tags if t not in NEVER_EMIT}
    schemes = {s.lower() for s in policy.allowed_url_schemes}
    out: list[str] = []
    dropped: list[dict[str, Any]] = []
    open_stack: list[str] = []
    drop_stack: list[str] = []

    for tok in tokens:
        if drop_stack:
            # Swallowing the contents of a dropped element. Track nesting of
            # droppable elements so the matching end tag is found.
            if (
                isinstance(tok, StartTag)
                and tok.name in DROP_WITH_CONTENTS
                and tok.name not in VOID_TAGS
                and not tok.self_closing
            ):
                drop_stack.append(tok.name)
            elif isinstance(tok, EndTag) and tok.name == drop_stack[-1]:
                drop_stack.pop()
            continue

        if isinstance(tok, Doctype):
            continue  # doctype may be omitted; not a drop
        if isinstance(tok, Comment):
            dropped.append({"kind": "comment", "reason": "dropped_comment"})
            continue
        if isinstance(tok, Text):
            out.append(_escape_text(tok.data.replace("\x00", "")))
            continue

        if isinstance(tok, StartTag):
            name = tok.name
            if name in NEVER_EMIT or name not in allowed:
                dropped.append({"kind": "tag", "name": name, "reason": "dropped_tag"})
                if (
                    name in DROP_WITH_CONTENTS
                    and name not in VOID_TAGS
                    and not tok.self_closing
                ):
                    dropped.append(
                        {"kind": "content", "name": name, "reason": "dropped_content"}
                    )
                    drop_stack.append(name)
                continue
            kept = _filter_attrs(name, tok.attrs, policy, schemes, dropped)
            parts = ["<", name]
            for aname, aval in kept:
                parts.append(f' {aname}="{_escape_attr(aval)}"')
            parts.append(">")
            out.append("".join(parts))
            if name not in VOID_TAGS:
                open_stack.append(name)
            continue

        if isinstance(tok, EndTag):
            name = tok.name
            if name in open_stack:
                while open_stack:
                    top = open_stack.pop()
                    out.append(f"</{top}>")
                    if top == name:
                        break
            else:
                dropped.append({"kind": "tag", "name": name, "reason": "dropped_tag"})
            continue

    while open_stack:
        out.append(f"</{open_stack.pop()}>")
    html = "".join(out).replace("\x00", "")
    return html, dropped


def _verify(html: str, policy: Policy) -> bool:
    """Re-tokenize the output and confirm the policy contract holds."""
    allowed = {t for t in policy.allowed_tags if t not in NEVER_EMIT}
    schemes = {s.lower() for s in policy.allowed_url_schemes}
    for tok in tokenize(html):
        if isinstance(tok, Comment):
            return False
        if isinstance(tok, StartTag):
            if tok.name not in allowed:
                return False
            for name, value in tok.attrs:
                if not name or not _ATTR_NAME_RE.match(name):
                    return False
                if name.lower().startswith("on"):
                    return False
                if name not in policy.allowed_attrs:
                    return False
                if name in policy.url_attrs and not _valid_url(value, schemes):
                    return False
    return True


def _deny(note: str) -> tuple[str, dict[str, Any]]:
    html = "<div></div>"
    return html, {
        "decision": "deny",
        "reason_codes": ["malformed"],
        "dropped": [],
        "output_bytes": len(html.encode("utf-8")),
        "note": note,
    }


def sanitize_tokens(tokens: list[Token], policy: Policy) -> tuple[str, dict[str, Any]]:
    html, dropped = _clean(tokens, policy)
    if not _verify(html, policy):
        return _deny("serialization failed the re-tokenize policy check")
    decision = "cleaned" if dropped else "allow"
    report: dict[str, Any] = {
        "decision": decision,
        "reason_codes": sorted({d["reason"] for d in dropped}),
        "dropped": dropped,
        "output_bytes": len(html.encode("utf-8")),
    }
    return html, report
