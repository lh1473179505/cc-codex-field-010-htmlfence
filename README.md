# htmlfence

A conservative HTML cleaner for snippets that will be stored and later shown in an admin page. `tokenize` turns a file into a token stream; `sanitize` filters that stream under a policy and serializes a stable output document.

The important property is not just "drop script tags once". After the cleaner writes HTML, that output has to be parsed again (with this same tokenizer) without growing back a forbidden tag, an event handler, or a `javascript:` URL. Several samples under `fixtures/mxss/` are cases where a careless strip-and-join will resurrect a script.

## Requirements

- Python 3.11+, standard library only
- No containers, no native HTML parser bindings, no network fetches of the document

## Already working

```bash
python -m htmlfence tokenize --input fixtures/benign.html
python -m htmlfence tokenize --input fixtures/script.html
python -m htmlfence tokenize --input fixtures/mxss/noscript.html
```

Policy is in `fixtures/policy.json`. Cleaning rules are in `docs/sanitizer.md`. The report object is in `docs/report-schema.md`.

## Intended CLI

```bash
python -m htmlfence sanitize \
  --input fixtures/script.html \
  --policy fixtures/policy.json \
  --out /tmp/htmlfence-out.html \
  --report /tmp/htmlfence-report.json
```

Parameter names are fixed in `htmlfence/__main__.py`. Keep them. Reuse the existing tokenizer; do not replace it with an external parser.

## Layout

- `htmlfence/tokenize.py` — tokenizer (data, tags, comments, RCDATA, RAWTEXT)
- `htmlfence/policy.py` — policy loader
- `htmlfence/engine.py` — `sanitize_tokens` (drop rules, URL checks, serialization)
- `fixtures/mxss/` — mutation-XSS shaped inputs
