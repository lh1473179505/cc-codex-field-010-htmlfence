"""CLI. tokenize already works; sanitize is the piece to implement."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, is_dataclass
from pathlib import Path

from htmlfence.policy import PolicyError, load_policy
from htmlfence.tokenize import tokenize
from htmlfence.tokens import StartTag


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="htmlfence")
    sub = p.add_subparsers(dest="cmd", required=True)

    tok = sub.add_parser("tokenize", help="print the token stream for an HTML file")
    tok.add_argument("--input", required=True)

    san = sub.add_parser("sanitize", help="filter and serialize HTML under a policy")
    san.add_argument("--input", required=True)
    san.add_argument("--policy", required=True)
    san.add_argument("--out", required=True)
    san.add_argument("--report", required=True)
    return p


def _read_input(path: str) -> str:
    raw = Path(path).read_bytes()
    return raw.decode("utf-8", "replace")


def _token_dump(token: object) -> dict:
    if is_dataclass(token):
        d = asdict(token)
        d["kind"] = type(token).__name__
        return d
    return {"kind": type(token).__name__, "repr": repr(token)}


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        src = _read_input(args.input)
    except OSError as exc:
        print(f"failed to read input: {exc}", file=sys.stderr)
        return 2

    tokens = tokenize(src)
    if args.cmd == "tokenize":
        print(json.dumps([_token_dump(t) for t in tokens], ensure_ascii=False, indent=2))
        return 0

    if args.cmd == "sanitize":
        try:
            policy = load_policy(args.policy)
        except (PolicyError, OSError) as exc:
            print(f"failed to load policy: {exc}", file=sys.stderr)
            return 2
        from htmlfence.engine import sanitize_tokens

        try:
            html, report = sanitize_tokens(tokens, policy)
        except NotImplementedError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(html, encoding="utf-8")
        Path(args.report).parent.mkdir(parents=True, exist_ok=True)
        Path(args.report).write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        decision = str(report.get("decision", "")).lower()
        if decision in ("allow", "cleaned"):
            return 0
        if decision == "deny":
            return 1
        print("report is missing a decision of allow, cleaned, or deny", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
