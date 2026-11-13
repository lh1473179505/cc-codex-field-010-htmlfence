"""A pragmatic HTML tokenizer used by inspect/tokenize.

It is not a complete HTML5 implementation, but it does handle the states
needed for the fixtures and for a conservative sanitizer: data, tags,
attributes, comments, doctype, RCDATA, and RAWTEXT. Character references
support the named entities listed in NAMED and numeric &#...; / &#x...;.
"""

from __future__ import annotations

from htmlfence.tokens import (
    RAWTEXT_TAGS,
    RCDATA_TAGS,
    Comment,
    Doctype,
    EndTag,
    StartTag,
    Text,
    Token,
)

NAMED = {
    "amp": "&",
    "lt": "<",
    "gt": ">",
    "quot": '"',
    "apos": "'",
    "nbsp": "\u00a0",
}


def tokenize(src: str) -> list[Token]:
    if "\x00" in src:
        src = src.replace("\x00", "")
    return _Tokenizer(src).run()


class _Tokenizer:
    def __init__(self, src: str) -> None:
        self.s = src
        self.i = 0
        self.n = len(src)
        self.out: list[Token] = []
        self.state = "data"
        self.raw_end: str | None = None

    def run(self) -> list[Token]:
        while self.i < self.n:
            if self.state == "data":
                self._data()
            elif self.state in ("rawtext", "rcdata"):
                self._rawish()
            else:
                raise RuntimeError(f"unknown state {self.state}")
        return self._coalesce_text(self.out)

    def _peek(self, k: int = 0) -> str:
        j = self.i + k
        return self.s[j] if j < self.n else ""

    def _starts(self, lit: str) -> bool:
        return self.s.startswith(lit, self.i)

    def _data(self) -> None:
        if self._starts("<!--"):
            self._comment()
            return
        if self._starts("<!DOCTYPE") or self._starts("<!doctype"):
            self._doctype()
            return
        if self._starts("<![CDATA["):
            # In HTML, CDATA is only meaningful in foreign content; treat
            # the bytes as text so a sanitizer can escape them.
            self.i += 9
            end = self.s.find("]]>", self.i)
            if end < 0:
                self.out.append(Text(self.s[self.i :]))
                self.i = self.n
            else:
                self.out.append(Text(self.s[self.i : end]))
                self.i = end + 3
            return
        if self._peek() == "<" and self._is_tag_start():
            self._tag()
            return
        # text until next '<' that looks like a tag, comment, or doctype
        start = self.i
        self.i += 1
        while self.i < self.n:
            if self._peek() == "<" and (
                self._is_tag_start() or self._starts("<!--") or self._starts("<!")
            ):
                break
            self.i += 1
        self.out.append(Text(self._unescape(self.s[start : self.i])))

    def _is_tag_start(self) -> bool:
        if self._peek() != "<":
            return False
        nxt = self._peek(1)
        if nxt == "/":
            nxt = self._peek(2)
        return nxt.isalpha() or nxt in "?!"

    def _comment(self) -> None:
        self.i += 4
        end = self.s.find("-->", self.i)
        # Also stop at a malformed closer `--!>` used in some mXSS cases,
        # but keep the recorded comment data as the literal span.
        end2 = self.s.find("--!>", self.i)
        use_bang = end2 >= 0 and (end < 0 or end2 < end)
        if use_bang:
            self.out.append(Comment(self.s[self.i : end2]))
            self.i = end2 + 4
            return
        if end < 0:
            self.out.append(Comment(self.s[self.i :]))
            self.i = self.n
            return
        self.out.append(Comment(self.s[self.i : end]))
        self.i = end + 3

    def _doctype(self) -> None:
        start = self.i
        end = self.s.find(">", self.i)
        if end < 0:
            self.out.append(Doctype(self.s[start:]))
            self.i = self.n
        else:
            self.out.append(Doctype(self.s[start : end + 1]))
            self.i = end + 1

    def _tag(self) -> None:
        assert self._peek() == "<"
        self.i += 1
        is_end = False
        if self._peek() == "/":
            is_end = True
            self.i += 1
        name = self._tag_name()
        if name == "":
            self.out.append(Text("<" + ("/" if is_end else "")))
            return
        attrs: list[tuple[str, str]] = []
        self_closing = False
        if not is_end:
            attrs, self_closing = self._attrs()
        else:
            # consume junk up to >
            while self.i < self.n and self._peek() not in ">/":
                if self._peek().isspace():
                    self.i += 1
                    continue
                # ignore unexpected attributes on end tags
                if self._peek().isalpha():
                    _n, _v = self._one_attr()
                else:
                    self.i += 1
            if self._peek() == "/":
                self.i += 1
            if self._peek() == ">":
                self.i += 1
        if is_end:
            self.out.append(EndTag(name))
            self.state = "data"
            self.raw_end = None
            return
        self.out.append(StartTag(name, attrs, self_closing))
        if self_closing or name in ("br", "img", "hr", "meta", "link", "input", "base", "col", "embed", "area", "source", "track", "wbr", "param"):
            return
        if name in RAWTEXT_TAGS:
            self.state = "rawtext"
            self.raw_end = name
        elif name in RCDATA_TAGS:
            self.state = "rcdata"
            self.raw_end = name

    def _tag_name(self) -> str:
        start = self.i
        while self.i < self.n and (self._peek().isalnum() or self._peek() in ":-"):
            self.i += 1
        return self.s[start : self.i].lower()

    def _attrs(self) -> tuple[list[tuple[str, str]], bool]:
        attrs: list[tuple[str, str]] = []
        self_closing = False
        while self.i < self.n:
            ch = self._peek()
            if ch.isspace() or ch in "\n\r\t\f":
                self.i += 1
                continue
            if ch == ">":
                self.i += 1
                break
            if ch == "/":
                # possible self-closing
                self.i += 1
                while self._peek().isspace():
                    self.i += 1
                if self._peek() == ">":
                    self.i += 1
                    self_closing = True
                    break
                continue
            name, value = self._one_attr()
            if name:
                attrs.append((name, value))
        return attrs, self_closing

    def _one_attr(self) -> tuple[str, str]:
        start = self.i
        while self.i < self.n and self._peek() not in ">=/\t\n\r\f ":
            self.i += 1
        name = self.s[start : self.i].lower()
        while self._peek().isspace():
            self.i += 1
        if self._peek() != "=":
            return name, ""
        self.i += 1
        while self._peek().isspace():
            self.i += 1
        q = self._peek()
        if q in ('"', "'"):
            self.i += 1
            start = self.i
            while self.i < self.n and self._peek() != q:
                self.i += 1
            value = self._unescape(self.s[start : self.i])
            if self._peek() == q:
                self.i += 1
            return name, value
        start = self.i
        while self.i < self.n and self._peek() not in ">\t\n\r\f /":
            self.i += 1
        return name, self._unescape(self.s[start : self.i])

    def _rawish(self) -> None:
        assert self.raw_end is not None
        closer = f"</{self.raw_end}"
        start = self.i
        while self.i < self.n:
            if self.s.lower().startswith(closer, self.i):
                # closer must be followed by space, `/`, or `>`
                after = self.i + len(closer)
                nxt = self.s[after] if after < self.n else ""
                if nxt in " \t\n\r\f/>" or nxt == "":
                    break
            self.i += 1
        raw = self.s[start : self.i]
        if self.state == "rcdata":
            raw = self._unescape(raw)
        if raw:
            self.out.append(Text(raw))
        self.state = "data"
        # let _tag consume the end tag on the next loop
        self.raw_end = None

    def _unescape(self, text: str) -> str:
        out: list[str] = []
        i = 0
        n = len(text)
        while i < n:
            if text[i] != "&":
                out.append(text[i])
                i += 1
                continue
            semi = text.find(";", i + 1)
            if semi < 0 or semi - i > 32:
                out.append("&")
                i += 1
                continue
            body = text[i + 1 : semi]
            if body.startswith("#x") or body.startswith("#X"):
                try:
                    cp = int(body[2:], 16)
                    out.append(chr(cp) if cp != 0 else "")
                    i = semi + 1
                    continue
                except ValueError:
                    out.append("&")
                    i += 1
                    continue
            if body.startswith("#"):
                try:
                    cp = int(body[1:], 10)
                    out.append(chr(cp) if cp != 0 else "")
                    i = semi + 1
                    continue
                except ValueError:
                    out.append("&")
                    i += 1
                    continue
            if body.lower() in NAMED:
                out.append(NAMED[body.lower()])
                i = semi + 1
                continue
            out.append("&")
            i += 1
        return "".join(out)

    @staticmethod
    def _coalesce_text(tokens: list[Token]) -> list[Token]:
        out: list[Token] = []
        for tok in tokens:
            if isinstance(tok, Text) and out and isinstance(out[-1], Text):
                out[-1] = Text(out[-1].data + tok.data)
            else:
                out.append(tok)
        return out
