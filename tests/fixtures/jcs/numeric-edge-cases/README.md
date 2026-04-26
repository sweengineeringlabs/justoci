# numeric-edge-cases — JCS number round-tripping

JCS specifies that numbers serialise in [RFC 8785 §3.2.2.3](
https://datatracker.ietf.org/doc/html/rfc8785#section-3.2.2.3),
which delegates to ECMA-262 §7.1.12.1 — the *shortest* decimal that
round-trips back to the same IEEE-754 double. Differences between
language number-printing libraries are the canonical way two JCS
implementations diverge.

This fixture exercises:

- TOML octal literals (`mode = 0o644`) that MUST be projected as
  decimal integers (`420`), not preserved as TOML strings or
  octal-prefixed numbers.
- TOML integer separators (`4_194_304`) that the TOML parser strips
  before yielding an `i64`. A re-impl that round-trips through string
  form would re-emit the underscores and mismatch.
- Boundary integers near `i32` min/max, cleared as plain decimals.
- `-0` (negative zero, integer) — TOML accepts the literal but the
  canonical form is `0`, not `-0`. A re-impl emitting `-0` mismatches.
- `0.1` — repeating binary fraction; ECMA-262 emits the shortest
  decimal that round-trips (`0.1`), not the full IEEE-754 expansion.
- `0.5` — exact in binary; canonical form is `0.5`, not `5e-1`.
- `1e21` — at this magnitude ECMA-262 switches to scientific
  notation. Some libraries switch earlier or use different exponent
  formats (`1E+21` vs `1e+21`); JCS mandates lowercase `e` and `+`
  on positive exponents.
- `1.0` — float with zero fraction. ECMA-262 §7.1.12.1 emits the
  shortest decimal that round-trips, so this serialises as `1`,
  not `1.0`. A re-impl that preserves the trailing `.0` (Python's
  `json.dumps(1.0)` emits `"1.0"`) will mismatch.

## Bug it catches in cross-language re-implementations

- A Python re-impl using `json.dumps(0.1)` directly emits `"0.1"`
  via Python's float repr (which itself follows ECMA-262 since
  Python 3.1), so it should agree. But a Python re-impl that uses
  `repr()` on a `Decimal` would emit `"0.1"` too — but a re-impl
  that pre-formats numbers via `"%.17g"` would emit
  `"0.10000000000000001"`, mismatching.
- A Go re-impl that calls `strconv.FormatFloat(0.1, 'g', -1, 64)`
  emits `"0.1"` correctly. One that uses `'f'` would emit
  `"0.100000"` and mismatch.
- A re-impl that quotes integers larger than 2^53 — sometimes done
  to avoid precision loss in JSON consumers — would emit
  `"size_bytes_large": "4194304"` instead of the unquoted integer.
- A re-impl that retains the source `mode = 0o644` as `"0o644"` (a
  string) instead of decoding to the decimal integer 420 would
  diverge on the layer-files block.
