# unicode-strings — non-ASCII string handling

`description`, `[config]`, and `[annotations]` carry non-ASCII content
across several Unicode subsystems:

- Multi-byte BMP characters (CJK: `日本語`, Cyrillic, Spanish accents).
- Astral-plane characters via UTF-16 surrogate pairs (rocket emoji
  `🚀` = U+1F680).
- Right-to-left scripts (Hebrew `שלום`).
- Pre-composed *and* combining-form versions of the same grapheme
  (`naïve` written two ways: `na\u00EFve` vs `nai\u0308ve`). The
  hash MUST treat these as different — JCS does not normalise.
- A non-ASCII *key* in `[config]` (`emoji_key_🚀`). JCS sorts keys by
  UTF-8 code-unit order, which is what the Rust `BTreeMap`
  iteration order gives us, and a Go re-impl using
  `gowebpki/jcs` should agree byte-for-byte.

## Bug it catches in cross-language re-implementations

- A Go re-impl that calls `json.Marshal(value)` (default behaviour:
  escape `<`, `>`, `&` as `\u003c`, `\u003e`, `\u0026`) before
  feeding to JCS would produce different bytes than the Rust impl
  on a description like `"a < b"`. JCS itself does *not* perform
  HTML escaping, so the Go impl must use a JSON encoder configured
  with `SetEscapeHTML(false)` or call `gowebpki/jcs` directly.
- A Python re-impl using `json.dumps(..., ensure_ascii=True)`
  (the default) would emit `"\u65e5\u672c\u8a9e"` for `日本語`
  while JCS requires the raw UTF-8 bytes (`ensure_ascii=False`).
- A re-impl that auto-normalises strings (NFC/NFD) would collapse
  the combining-form `naïve` into the pre-composed form (or vice
  versa) and hash differently from the Rust impl. JCS preserves
  the codepoint sequence as-given.
- A re-impl that handles BMP characters but drops or replaces
  astral-plane codepoints would fail on the rocket emoji.
