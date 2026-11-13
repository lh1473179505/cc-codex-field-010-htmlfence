# Report schema

```json
{
  "decision": "cleaned",
  "reason_codes": ["dropped_tag", "dropped_attr", "dropped_url"],
  "dropped": [
    {"kind": "tag", "name": "script", "reason": "dropped_tag"},
    {"kind": "attr", "name": "href", "tag": "a", "reason": "dropped_url"}
  ],
  "output_bytes": 120
}
```

- `decision` is `allow`, `cleaned`, or `deny`.
- `reason_codes` is the unique set of reasons recorded in `dropped`. It is empty on `allow`.
- Known reasons: `dropped_tag`, `dropped_content`, `dropped_attr`, `dropped_url`, `dropped_comment`, `malformed`.
- `output_bytes` is the UTF-8 length of `--out`.
