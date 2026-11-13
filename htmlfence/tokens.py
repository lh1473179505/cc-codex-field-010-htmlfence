"""Token types produced by the tokenizer."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class StartTag:
    name: str
    attrs: list[tuple[str, str]]
    self_closing: bool = False


@dataclass
class EndTag:
    name: str


@dataclass
class Text:
    data: str


@dataclass
class Comment:
    data: str


@dataclass
class Doctype:
    data: str


Token = StartTag | EndTag | Text | Comment | Doctype


RAWTEXT_TAGS = frozenset({
    "script", "style", "iframe", "noembed", "noframes", "xmp", "noscript", "plaintext",
})
RCDATA_TAGS = frozenset({"title", "textarea"})
VOID_TAGS = frozenset({
    "area", "base", "br", "col", "embed", "hr", "img", "input",
    "link", "meta", "param", "source", "track", "wbr",
})
