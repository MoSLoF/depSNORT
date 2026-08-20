package registry

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"ihbv.io/depsnort/internal/datasource"
)

// makeCrate builds a .crate (gzip tar) from a name-version dir and a file map.
func makeCrate(dir string, files map[string]string) []byte {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range files {
		full := dir + "/" + name
		_ = tw.WriteHeader(&tar.Header{Name: full, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg})
		_, _ = tw.Write([]byte(body))
	}
	_ = tw.Close()
	_ = gz.Close()
	return buf.Bytes()
}

func TestExtractBuildRS(t *testing.T) {
	crate := makeCrate("foo-1.0.0", map[string]string{
		"Cargo.toml": "[package]\nname=\"foo\"\n",
		"build.rs":   "fn main(){ reqwest::get(c2); }",
		"src/lib.rs": "pub fn x(){}", // nested, must be ignored (only top-level build.rs)
		"../evil.rs": "traversal",    // refused
	})
	b, found, err := extractBuildRS(crate)
	if err != nil || !found {
		t.Fatalf("found=%v err=%v", found, err)
	}
	if !strings.Contains(string(b), "reqwest::get") {
		t.Errorf("build.rs content = %q", string(b))
	}
}

func TestExtractBuildRS_None(t *testing.T) {
	crate := makeCrate("foo-1.0.0", map[string]string{"Cargo.toml": "[package]\n"})
	if _, found, err := extractBuildRS(crate); found || err != nil {
		t.Errorf("a crate with no build.rs must report found=false, got found=%v err=%v", found, err)
	}
}

// crateDoer routes /versions to JSON and static.crates.io to the .crate bytes.
type crateDoer struct {
	versionsJSON string
	crate        []byte
}

func (d *crateDoer) Do(req *http.Request) (*http.Response, error) {
	resp := func(body io.Reader) *http.Response {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(body), Header: make(http.Header)}
	}
	if strings.Contains(req.URL.Path, "/versions") {
		return resp(strings.NewReader(d.versionsJSON)), nil
	}
	if req.URL.Host == "static.crates.io" {
		return resp(bytes.NewReader(d.crate)), nil
	}
	return &http.Response{StatusCode: 404, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
}

func newTestCrateSource(t *testing.T, d Doer) *CrateSourceClient {
	return &CrateSourceClient{HTTP: d, Cache: datasource.NewCache(t.TempDir(), time.Hour), Now: func() time.Time { return time.Unix(1, 0) }}
}

func TestCrateSourceResolveBuildRS(t *testing.T) {
	crate := makeCrate("proc-macro1-1.0.0", map[string]string{
		"Cargo.toml": "[package]\nname=\"proc-macro1\"\n",
		"build.rs":   "fn main(){ let p = base64::decode(host); std::process::Command::new(\"sh\"); reqwest::get(c2); }",
	})
	sum := sha256.Sum256(crate)
	ck := hex.EncodeToString(sum[:])
	d := &crateDoer{
		versionsJSON: `{"versions":[{"num":"1.0.0","yanked":false,"checksum":"` + ck + `"}]}`,
		crate:        crate,
	}
	cs := newTestCrateSource(t, d)
	b, ver, found, err := cs.ResolveBuildRS(context.Background(), "proc-macro1", "^1.0")
	if err != nil || !found {
		t.Fatalf("found=%v err=%v", found, err)
	}
	if ver != "1.0.0" {
		t.Errorf("resolved version = %q, want 1.0.0", ver)
	}
	if !strings.Contains(string(b), "reqwest::get") {
		t.Errorf("build.rs = %q", string(b))
	}
}

// A wrong checksum must fail closed — never analyze bytes that don't match what
// crates.io published.
func TestCrateSourceChecksumMismatch(t *testing.T) {
	crate := makeCrate("evil-1.0.0", map[string]string{"build.rs": "fn main(){}"})
	d := &crateDoer{
		versionsJSON: `{"versions":[{"num":"1.0.0","yanked":false,"checksum":"deadbeef"}]}`,
		crate:        crate,
	}
	cs := newTestCrateSource(t, d)
	if _, _, _, err := cs.ResolveBuildRS(context.Background(), "evil", "^1.0"); err == nil {
		t.Error("checksum mismatch must return an error, not the (unverified) build.rs")
	}
}

// A yanked-only version list resolves to nothing (a build would not pull it).
func TestCrateSourceSkipsYanked(t *testing.T) {
	d := &crateDoer{versionsJSON: `{"versions":[{"num":"1.0.0","yanked":true,"checksum":"x"}]}`}
	cs := newTestCrateSource(t, d)
	if _, _, found, err := cs.ResolveBuildRS(context.Background(), "gone", "^1.0"); found || err != nil {
		t.Errorf("only-yanked crate must resolve to nothing, got found=%v err=%v", found, err)
	}
}
