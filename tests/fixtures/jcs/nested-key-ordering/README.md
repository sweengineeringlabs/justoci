# nested-key-ordering — recursive lex-sort

JCS requires lexicographic (UTF-8 code-unit) key sorting at *every*
nesting level. The spec writes `[config]` keys and inline-table
entries in deliberately non-alphabetical order; the canonical
output must show them sorted at the top, sub-, sub-sub-, and
sub-sub-sub level, plus inside each entry of an array of tables.

The fixture also includes annotation keys that test string-vs-numeric
sorting: `vendor.foo.10` sorts BEFORE `vendor.foo.2` under
lexicographic ordering (because `'1' < '2'` then `'0' < '.'`),
which is correct per JCS but counter-intuitive for humans.

## Bug it catches in cross-language re-implementations

- A re-impl that calls JCS only on the top-level object and
  forgets to recurse — or that uses a sort-once-at-the-end strategy
  rather than relying on JCS's per-level recursion — will diverge
  on the `config.network.tls.ciphers` block.
- A Go re-impl that uses `map[string]interface{}` and feeds the
  result to `gowebpki/jcs` will be fine because Go maps emit in
  random order and JCS resorts. A re-impl that uses an *ordered*
  map (`yaml.MapSlice`, an OAS-style ordered object) and feeds
  the source order to `json.Marshal` *without* JCS would emit the
  source order, mismatching.
- A re-impl that calls Python's `json.dumps(obj, sort_keys=True)`
  and skips JCS entirely would mostly agree on key order BUT
  would emit `\u00xx` escapes for non-ASCII (see
  `unicode-strings/`) — so the bug surfaces only when both
  fixtures are run together.
- A re-impl that sorts numerically (`vendor.foo.10` after
  `vendor.foo.2`) — easy to do via a "natural sort" library —
  diverges on the annotations.
- An array of tables (`[[config.routes]]`) where the source-order
  keys are reordered would mismatch under a re-impl that
  preserves array element ordering (correct) but fails to re-sort
  each element's keys (incorrect).
