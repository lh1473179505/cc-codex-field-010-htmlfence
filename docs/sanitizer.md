# Sanitizer rules

`sanitize` reads tokens, drops or rewrites what the policy forbids, and writes a serialization to `--out`. The serialization is the contract: running `tokenize` on `--out` must not produce a start tag whose name is outside `allowed_tags`, an attribute outside `allowed_attrs`, an `on*` event handler, or a URL attribute with a disallowed scheme.

If the input is so malformed that a conservative serialization cannot be produced, the report decision is `deny`, `--out` should be an empty document (empty file or a single empty `<div></div>` is acceptable if documented in the report), and the process exits 1. Ordinary dirty input that can be cleaned is `cleaned` (exit 0). Purely clean input that needed no drops may be `allow` (exit 0). Implementation faults exit 2.

## Drops

- Comments are dropped when `drop_comments` is true (the public policy).
- Doctype may be omitted from the output.
- A start tag whose name is not in `allowed_tags` is dropped. Its inner tokens are still processed, except for `script`, `style`, `iframe`, `object`, `embed`, `link`, `meta`, `base`, `form`, `textarea`, `title`, `noscript`, `noembed`, `noframes`, `xmp`, `plaintext`, `svg`, `math`, and `template`: those elements are dropped *with* their contents, up to the matching end tag (or until the RAWTEXT/RCDATA closer the tokenizer already consumed).
- End tags for dropped elements are dropped.
- Attributes not listed in `allowed_attrs` are dropped. Any attribute whose name starts with `on` (case-insensitive) is dropped even if a policy author later adds it.
- Attribute names containing spaces, slashes, angle brackets, quotes, or `=` are dropped.
- `id` and `class` values may only contain letters, digits, hyphen, underscore, and spaces (for class lists). Other values are dropped.

## URL attributes

Names in `url_attrs` (`href` and `src` in the public policy) are parsed as URLs:

- Trim ASCII whitespace.
- If the value has a scheme (a leading alpha sequence followed by `:` before any `/`, `?`, or `#`), the scheme must be in `allowed_url_schemes`. Comparison is case-insensitive. Anything else, including `javascript:`, `data:`, `vbscript:`, `file:`, and `http:` with extra leading whitespace or control characters, is dropped (the whole attribute, not the tag).
- Scheme-relative (`//example.test/x`) and path-relative (`/x`, `./x`, `foo/bar`) values are allowed, except a relative value that embeds `\` or a raw `<`.
- Reject a value that contains `javascript:` after HTML whitespace or after a leading control character has been removed.

## Serialization (this is the mXSS-sensitive part)

- Serialize text with `&`, `<`, and `>` escaped as `&amp;`, `&lt;`, `&gt;`. In attribute values also escape `"` as `&quot;`. Do not emit unescaped `&` that could start a character reference.
- Attribute values are always double-quoted. Never emit an unquoted or single-quoted attribute.
- Do not emit comments, CDATA wrappers, or a `noscript` / `xmp` / `iframe` / `script` / `style` / `svg` / `math` / `template` element, even if a future policy lists them. Those elements have parser-dependent contents and are out of scope for this cleaner.
- Void tags (`br`, `img`, `hr`, `input`, `meta`, `link`, `base`, `col`, `embed`, `area`, `source`, `track`, `wbr`, `param`) are serialized as `<name ...>` without a closer. They must not be given children.
- Do not use optional-tag omission. If you emit a `<p>`, emit `</p>`.
- The output must be UTF-8. Do not emit a NUL byte.
- Stability: let `s1` be the output of `sanitize` and `s2` the output of running `sanitize` on `s1`. `s1` and `s2` must be identical, and tokenizing `s1` must not contain a dropped tag or attribute as defined above.

The samples under `fixtures/mxss/` are inputs, not expected outputs. A correct cleaner will strip or rewrite them so that a second tokenize pass sees no `script` start tag and no `onerror` attribute.
