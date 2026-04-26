// verify_go — cross-language JCS fixture verifier (Go side).
//
// For each fixture in tests/fixtures/jcs/<name>/, this program:
//
//  1. Loads spec.toml.
//  2. Projects it into a JSON tree following the same rules
//     spec/src/saf/canonicalize.rs::spec_to_json applies in Rust.
//  3. Runs RFC 8785 JCS via github.com/gowebpki/jcs.
//  4. Computes sha256 of the canonical bytes.
//  5. Asserts byte-equality against expected.canonical.json and
//     expected.spec_hash.
//
// Exit code:
//
//   0 — every fixture matches.
//   1 — at least one fixture mismatched (real bug — Go and Rust
//       impls disagree on the JCS canonical form).
//   2 — environment / fixture-loading failure (not a JCS-impl bug).
//
// This program intentionally does NOT depend on any Rust artifact
// at runtime. It re-implements the projection in Go so the fixture
// proves cross-language agreement, not that two halves of the
// same impl agree.

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/gowebpki/jcs"
)

// ---------------------------------------------------------------------------
// Raw spec — wire-shape mirror of spec/src/core/raw.rs::RawSpec.
// ---------------------------------------------------------------------------

type rawSpec struct {
	SpecVersion string                 `toml:"spec_version"`
	ID          string                 `toml:"id"`
	Kind        string                 `toml:"kind"`
	Description *string                `toml:"description"`
	Platform    *rawPlatform           `toml:"platform"`
	Layers      []rawLayer             `toml:"layers"`
	Config      map[string]interface{} `toml:"config"`
	Annotations map[string]string      `toml:"annotations"`
	Attestation *rawAttestation        `toml:"attestation"`
}

type rawPlatform struct {
	OS   *string `toml:"os"`
	Arch *string `toml:"arch"`
}

type rawLayer struct {
	Source      *string        `toml:"source"`
	MediaType   string         `toml:"media_type"`
	Compression *string        `toml:"compression"`
	Files       []rawLayerFile `toml:"files"`
}

type rawLayerFile struct {
	Source string `toml:"source"`
	Dest   string `toml:"dest"`
	Mode   uint32 `toml:"mode"`
}

type rawAttestation struct {
	SLSA *rawSLSA `toml:"slsa"`
	SBOM *rawSBOM `toml:"sbom"`
	Sign *rawSign `toml:"sign"`
}

type rawSLSA struct {
	Level     *int64  `toml:"level"`
	BuilderID *string `toml:"builder_id"`
}

type rawSBOM struct {
	Format *string `toml:"format"`
	Scope  *string `toml:"scope"`
}

type rawSign struct {
	Kind     *string `toml:"kind"`
	Identity *string `toml:"identity"`
}

// ---------------------------------------------------------------------------
// Projection — mirrors spec/src/saf/canonicalize.rs::spec_to_json.
// ---------------------------------------------------------------------------

// orderedField is one (key, value) pair in the projected JSON object.
// We use an ordered representation only for determinism in encoding —
// JCS will resort lexicographically anyway, but encoding into a
// stable order makes diff output readable.
type orderedField struct {
	key string
	val interface{}
}

// orderedObject is what we hand to encoding/json. We marshal it with
// keys in the order we inserted them; JCS resorts by UTF-8 codepoint.
type orderedObject []orderedField

func (o orderedObject) MarshalJSON() ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, f := range o {
		if i > 0 {
			buf.WriteByte(',')
		}
		k, err := json.Marshal(f.key)
		if err != nil {
			return nil, err
		}
		buf.Write(k)
		buf.WriteByte(':')
		v, err := json.Marshal(f.val)
		if err != nil {
			return nil, err
		}
		buf.Write(v)
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

func projectSpec(s *rawSpec) (orderedObject, error) {
	obj := orderedObject{
		{key: "spec_version", val: s.SpecVersion},
		{key: "id", val: s.ID},
		{key: "kind", val: s.Kind},
	}
	if s.Description != nil {
		obj = append(obj, orderedField{key: "description", val: *s.Description})
	}
	if p := projectPlatform(s.Platform); p != nil {
		obj = append(obj, orderedField{key: "platform", val: p})
	}
	layers, err := projectLayers(s.Layers)
	if err != nil {
		return nil, err
	}
	obj = append(obj, orderedField{key: "layers", val: layers})
	if c := projectConfig(s.Config); c != nil {
		obj = append(obj, orderedField{key: "config", val: c})
	}
	if a := projectAnnotations(s.Annotations); a != nil {
		obj = append(obj, orderedField{key: "annotations", val: a})
	}
	obj = append(obj, orderedField{key: "attestation", val: projectAttestation(s.Attestation)})
	return obj, nil
}

func projectPlatform(p *rawPlatform) interface{} {
	if p == nil {
		return nil
	}
	if p.OS == nil && p.Arch == nil {
		return nil
	}
	out := orderedObject{}
	if p.OS != nil {
		out = append(out, orderedField{key: "os", val: *p.OS})
	}
	if p.Arch != nil {
		out = append(out, orderedField{key: "arch", val: *p.Arch})
	}
	return out
}

func projectLayers(layers []rawLayer) ([]interface{}, error) {
	out := make([]interface{}, 0, len(layers))
	for i, l := range layers {
		// Validation — exactly one of source/files must be set.
		hasSource := l.Source != nil
		hasFiles := len(l.Files) > 0
		if hasSource && hasFiles {
			return nil, fmt.Errorf(
				"layer #%d: both `source` and `files` set", i)
		}
		if !hasSource && !hasFiles {
			return nil, fmt.Errorf(
				"layer #%d: neither `source` nor `files` set", i)
		}

		comp := defaultCompression(l.MediaType)
		if l.Compression != nil {
			comp = *l.Compression
		}

		obj := orderedObject{
			{key: "media_type", val: l.MediaType},
			{key: "compression", val: comp},
		}
		if hasSource {
			obj = append(obj, orderedField{
				key: "source",
				val: normalisePath(*l.Source),
			})
		} else {
			files := make([]interface{}, 0, len(l.Files))
			for _, f := range l.Files {
				files = append(files, orderedObject{
					{key: "source", val: normalisePath(f.Source)},
					{key: "dest", val: f.Dest},
					{key: "mode", val: int64(f.Mode)},
				})
			}
			obj = append(obj, orderedField{key: "files", val: files})
		}
		out = append(out, obj)
	}
	return out, nil
}

// projectConfig replicates the Rust toml_to_json + the ConfigBlob
// "empty object → omit" rule. Returns nil to mean "omit".
func projectConfig(c map[string]interface{}) interface{} {
	if len(c) == 0 {
		return nil
	}
	return tomlToJSON(c)
}

// tomlToJSON converts a toml-decoded value tree into a json-marshalable
// tree. Tables become orderedObject sorted lexicographically (matching
// the Rust BTreeMap traversal). The `mode` and other integer/float
// distinctions follow what BurntSushi/toml hands us:
//
//	bool        → bool
//	int64       → int64    (TOML integer)
//	float64     → float64  (TOML float)
//	string      → string
//	[]interface → []interface (recursive)
//	map[..]..   → orderedObject (sorted keys, recursive)
//	time.Time   → string (ISO8601 / RFC3339)
//
// JCS then re-sorts keys at encoding time — but pre-sorting here
// matches the Rust BTreeMap order one-for-one, which makes the
// encoded JSON byte-identical to the Rust impl BEFORE JCS even runs.
// (JCS is then idempotent on already-sorted input.)
func tomlToJSON(v interface{}) interface{} {
	switch x := v.(type) {
	case map[string]interface{}:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		// Lex byte sort matches Rust's BTreeMap<String, _> order.
		sort.Strings(keys)
		out := orderedObject{}
		for _, k := range keys {
			out = append(out, orderedField{key: k, val: tomlToJSON(x[k])})
		}
		return out
	case []map[string]interface{}:
		// BurntSushi/toml hands this for arrays-of-tables.
		out := make([]interface{}, 0, len(x))
		for _, e := range x {
			out = append(out, tomlToJSON(e))
		}
		return out
	case []interface{}:
		out := make([]interface{}, 0, len(x))
		for _, e := range x {
			out = append(out, tomlToJSON(e))
		}
		return out
	default:
		return v
	}
}

func projectAnnotations(a map[string]string) interface{} {
	if len(a) == 0 {
		return nil
	}
	keys := make([]string, 0, len(a))
	for k := range a {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := orderedObject{}
	for _, k := range keys {
		out = append(out, orderedField{key: k, val: a[k]})
	}
	return out
}

// projectAttestation always returns an object — the default block
// (SLSA L2, CycloneDX layers, cosign-keyless) is emitted even when
// the source TOML omits the section entirely.
func projectAttestation(a *rawAttestation) orderedObject {
	if a == nil {
		a = &rawAttestation{}
	}
	return orderedObject{
		{key: "slsa", val: projectSLSA(a.SLSA)},
		{key: "sbom", val: projectSBOM(a.SBOM)},
		{key: "sign", val: projectSign(a.Sign)},
	}
}

func projectSLSA(s *rawSLSA) orderedObject {
	level := int64(2) // default per spec
	var builder *string
	if s != nil {
		if s.Level != nil {
			level = *s.Level
		}
		builder = s.BuilderID
	}
	out := orderedObject{
		{key: "level", val: level},
	}
	if builder != nil {
		out = append(out, orderedField{key: "builder_id", val: *builder})
	}
	// Re-sort to match Rust's projection: the Rust impl inserts
	// "level" then conditionally "builder_id"; in BTreeMap-sorted
	// JSON output, "builder_id" sorts before "level" — but the
	// Rust impl uses serde_json::Map which preserves insertion
	// order, then JCS resorts. To make the pre-JCS bytes identical,
	// we sort here too. This is purely an aesthetic alignment;
	// JCS would resort either way.
	sortObject(out)
	return out
}

func projectSBOM(s *rawSBOM) orderedObject {
	format := "cyclonedx"
	scope := "layers"
	if s != nil {
		if s.Format != nil {
			format = *s.Format
		}
		if s.Scope != nil {
			scope = *s.Scope
		}
	}
	out := orderedObject{
		{key: "format", val: format},
		{key: "scope", val: scope},
	}
	sortObject(out)
	return out
}

func projectSign(s *rawSign) orderedObject {
	kind := "cosign-keyless"
	var identity *string
	if s != nil {
		if s.Kind != nil {
			kind = *s.Kind
		}
		identity = s.Identity
	}
	out := orderedObject{
		{key: "kind", val: kind},
	}
	if identity != nil {
		out = append(out, orderedField{key: "identity", val: *identity})
	}
	sortObject(out)
	return out
}

func sortObject(o orderedObject) {
	sort.Slice(o, func(i, j int) bool { return o[i].key < o[j].key })
}

func defaultCompression(mediaType string) string {
	if strings.HasSuffix(mediaType, "+gzip") {
		return "gzip"
	}
	if strings.HasSuffix(mediaType, "+zstd") {
		return "zstd"
	}
	return "none"
}

func normalisePath(p string) string {
	return strings.ReplaceAll(p, `\`, `/`)
}

// ---------------------------------------------------------------------------
// Driver — walk fixtures, verify each, report.
// ---------------------------------------------------------------------------

type fixtureResult struct {
	name string
	err  error
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: verify_go <fixtures-dir>")
		os.Exit(2)
	}
	root := os.Args[1]
	entries, err := os.ReadDir(root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read fixtures dir %q: %v\n", root, err)
		os.Exit(2)
	}

	var dirs []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		// Skip our own helper subdir.
		if e.Name() == "verify_go" {
			continue
		}
		spec := filepath.Join(root, e.Name(), "spec.toml")
		if _, err := os.Stat(spec); err == nil {
			dirs = append(dirs, e.Name())
		}
	}
	sort.Strings(dirs)
	if len(dirs) == 0 {
		fmt.Fprintf(os.Stderr, "no fixtures found under %q\n", root)
		os.Exit(2)
	}

	results := make([]fixtureResult, 0, len(dirs))
	for _, name := range dirs {
		err := verifyFixture(filepath.Join(root, name))
		results = append(results, fixtureResult{name: name, err: err})
	}

	pass, fail := 0, 0
	for _, r := range results {
		if r.err == nil {
			fmt.Printf("PASS  %s\n", r.name)
			pass++
		} else {
			fmt.Printf("FAIL  %s\n", r.name)
			fmt.Printf("       %v\n", r.err)
			fail++
		}
	}
	fmt.Printf("\n%d passed, %d failed (out of %d)\n", pass, fail, len(results))
	if fail > 0 {
		os.Exit(1)
	}
}

func verifyFixture(dir string) error {
	specPath := filepath.Join(dir, "spec.toml")
	bytesIn, err := os.ReadFile(specPath)
	if err != nil {
		return fmt.Errorf("read spec.toml: %w", err)
	}

	var raw rawSpec
	if err := toml.Unmarshal(bytesIn, &raw); err != nil {
		return fmt.Errorf("parse spec.toml: %w", err)
	}

	projected, err := projectSpec(&raw)
	if err != nil {
		return fmt.Errorf("project spec: %w", err)
	}

	encoded, err := json.Marshal(projected)
	if err != nil {
		return fmt.Errorf("marshal projected spec: %w", err)
	}

	// JCS — RFC 8785 canonicalisation.
	canonical, err := jcs.Transform(encoded)
	if err != nil {
		return fmt.Errorf("jcs transform: %w", err)
	}

	expectedCanonical, err := os.ReadFile(filepath.Join(dir, "expected.canonical.json"))
	if err != nil {
		return fmt.Errorf("read expected.canonical.json: %w", err)
	}
	if !bytes.Equal(canonical, expectedCanonical) {
		return canonicalDiff(canonical, expectedCanonical)
	}

	sum := sha256.Sum256(canonical)
	digest := "sha256:" + hex.EncodeToString(sum[:])

	expectedHash, err := os.ReadFile(filepath.Join(dir, "expected.spec_hash"))
	if err != nil {
		return fmt.Errorf("read expected.spec_hash: %w", err)
	}
	want := strings.TrimRight(string(expectedHash), "\n")
	if digest != want {
		return fmt.Errorf("spec_hash mismatch:\n  got:  %s\n  want: %s", digest, want)
	}
	return nil
}

// canonicalDiff returns a human-readable error describing where the
// Go-produced canonical bytes and the Rust-produced bytes diverge.
func canonicalDiff(got, want []byte) error {
	// First differing byte.
	n := len(got)
	if len(want) < n {
		n = len(want)
	}
	idx := -1
	for i := 0; i < n; i++ {
		if got[i] != want[i] {
			idx = i
			break
		}
	}
	if idx == -1 && len(got) != len(want) {
		idx = n
	}
	const window = 40
	startA, endA := windowBounds(idx, len(got), window)
	startB, endB := windowBounds(idx, len(want), window)
	return fmt.Errorf(
		"canonical bytes differ at offset %d:\n"+
			"  got  (%d bytes) ...%q...\n"+
			"  want (%d bytes) ...%q...",
		idx,
		len(got), string(got[startA:endA]),
		len(want), string(want[startB:endB]),
	)
}

func windowBounds(at, total, w int) (int, int) {
	start := at - w
	if start < 0 {
		start = 0
	}
	end := at + w
	if end > total {
		end = total
	}
	return start, end
}
