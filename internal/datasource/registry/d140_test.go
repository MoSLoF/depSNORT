package registry

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"path"
	"strings"
	"testing"
)

// D-140: analyzing a LOCKED cargo dependency needs its exact version, which is
// what BuildRSAt adds. ResolveBuildRS answers a different question — "what would
// a build pull for this requirement" — and deliberately skips yanked versions.
// Reusing it here would silently return nothing for a lockfile pinned to a
// version yanked after the fact, which is a common stale-lock state and exactly
// what the build still installs.

func TestD140BuildRSAtPicksTheExactVersion(t *testing.T) {
	// Two published versions; the newer one is NOT what the lockfile pins.
	oldCrate := makeCrate("libc-0.2.155", map[string]string{
		"Cargo.toml": "[package]\nname=\"libc\"\n",
		"build.rs":   "fn main(){ println!(\"cargo:rustc-cfg=old\"); }",
	})
	newCrate := makeCrate("libc-0.2.999", map[string]string{
		"Cargo.toml": "[package]\nname=\"libc\"\n",
		"build.rs":   "fn main(){ println!(\"cargo:rustc-cfg=new\"); }",
	})
	oldSum := sha256.Sum256(oldCrate)
	newSum := sha256.Sum256(newCrate)

	d := &versionRoutingDoer{
		versionsJSON: `{"versions":[
			{"num":"0.2.999","yanked":false,"checksum":"` + hex.EncodeToString(newSum[:]) + `"},
			{"num":"0.2.155","yanked":false,"checksum":"` + hex.EncodeToString(oldSum[:]) + `"}
		]}`,
		crates: map[string][]byte{"0.2.155": oldCrate, "0.2.999": newCrate},
	}
	cs := newTestCrateSource(t, d)

	b, found, err := cs.BuildRSAt(context.Background(), "libc", "0.2.155")
	if err != nil || !found {
		t.Fatalf("found=%v err=%v", found, err)
	}
	if !strings.Contains(string(b), "old") {
		t.Errorf("BuildRSAt returned the wrong version's build.rs: %q", string(b))
	}
}

// The differentiator, asserted as a contrast so the reason BuildRSAt exists is
// visible in the test rather than only in a comment.
func TestD140BuildRSAtReadsYankedWhereResolveDoesNot(t *testing.T) {
	crate := makeCrate("spin-0.9.8", map[string]string{
		"Cargo.toml": "[package]\nname=\"spin\"\n",
		"build.rs":   "fn main(){ println!(\"cargo:rustc-cfg=yanked_but_locked\"); }",
	})
	sum := sha256.Sum256(crate)
	versions := `{"versions":[{"num":"0.9.8","yanked":true,"checksum":"` + hex.EncodeToString(sum[:]) + `"}]}`

	// ResolveBuildRS: a build would not pull a yanked version, so it finds none.
	cs1 := newTestCrateSource(t, &versionRoutingDoer{
		versionsJSON: versions,
		crates:       map[string][]byte{"0.9.8": crate},
	})
	if _, _, found, err := cs1.ResolveBuildRS(context.Background(), "spin", "0.9.8"); found || err != nil {
		t.Errorf("ResolveBuildRS on a yanked-only crate should find nothing, got found=%v err=%v", found, err)
	}

	// BuildRSAt: the lockfile pins it, so it is what the build installs.
	cs2 := newTestCrateSource(t, &versionRoutingDoer{
		versionsJSON: versions,
		crates:       map[string][]byte{"0.9.8": crate},
	})
	b, found, err := cs2.BuildRSAt(context.Background(), "spin", "0.9.8")
	if err != nil || !found {
		t.Fatalf("BuildRSAt must read a locked-but-yanked version: found=%v err=%v", found, err)
	}
	if !strings.Contains(string(b), "yanked_but_locked") {
		t.Errorf("build.rs = %q", string(b))
	}
}

// Exactness must not cost integrity checking.
func TestD140BuildRSAtVerifiesChecksum(t *testing.T) {
	crate := makeCrate("evil-1.0.0", map[string]string{"build.rs": "fn main(){}"})
	cs := newTestCrateSource(t, &versionRoutingDoer{
		versionsJSON: `{"versions":[{"num":"1.0.0","yanked":false,"checksum":"deadbeef"}]}`,
		crates:       map[string][]byte{"1.0.0": crate},
	})
	if _, _, err := cs.BuildRSAt(context.Background(), "evil", "1.0.0"); err == nil {
		t.Error("checksum mismatch must error, not return unverified bytes")
	}
}

// A version the registry does not list is not an error — there is simply
// nothing to analyze.
func TestD140BuildRSAtUnknownVersion(t *testing.T) {
	cs := newTestCrateSource(t, &versionRoutingDoer{
		versionsJSON: `{"versions":[{"num":"1.0.0","yanked":false,"checksum":"x"}]}`,
	})
	if _, found, err := cs.BuildRSAt(context.Background(), "foo", "9.9.9"); found || err != nil {
		t.Errorf("unknown version: want found=false err=nil, got found=%v err=%v", found, err)
	}
}

// versionRoutingDoer serves per-version .crate bytes, so a test can prove which
// version was actually fetched rather than only that something was.
type versionRoutingDoer struct {
	versionsJSON string
	crates       map[string][]byte // version -> .crate bytes
}

func (d *versionRoutingDoer) Do(req *http.Request) (*http.Response, error) {
	ok := func(body []byte) *http.Response {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(body)), Header: make(http.Header)}
	}
	if strings.Contains(req.URL.Path, "/versions") {
		return ok([]byte(d.versionsJSON)), nil
	}
	if req.URL.Host == "static.crates.io" {
		// .../crates/<name>/<name>-<version>.crate
		base := path.Base(req.URL.Path)
		base = strings.TrimSuffix(base, ".crate")
		if i := strings.LastIndex(base, "-"); i >= 0 {
			if c, found := d.crates[base[i+1:]]; found {
				return ok(c), nil
			}
		}
	}
	return &http.Response{StatusCode: 404, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
}
