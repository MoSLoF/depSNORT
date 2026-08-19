package pypi

import (
	"archive/tar"
	"bytes"
	"testing"
)

// tarSeed builds a one-entry tar for seeding the archive fuzzer. Errors are
// ignored: a seed that fails to build simply is not added.
func tarSeed(name, content string) []byte {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	_ = tw.WriteHeader(&tar.Header{
		Name: name, Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg,
	})
	_, _ = tw.Write([]byte(content))
	_ = tw.Close()
	return buf.Bytes()
}

// FuzzParseRequirements drives arbitrary bytes at the requirements.txt parser,
// which is line-oriented and handles pip-compile "# via" provenance comments —
// exactly the sort of hand-rolled scanner where a malformed line becomes a panic
// (D-33).
func FuzzParseRequirements(f *testing.F) {
	f.Add([]byte("flask==2.0.1\nrequests==2.31.0\n"))
	f.Add([]byte("aiohttp==3.9.1\n    # via -r requirements.in\n"))
	f.Add([]byte("pkg==1.0 # via parent\n-e .\n-r other.txt\n"))
	f.Add([]byte("Flask_SQLAlchemy==1.0\n--hash=sha256:deadbeef\n"))
	f.Add([]byte("unpinned-package\n>=1.0\n===\n"))
	f.Add([]byte("# via\n#via\n   # via   \n"))
	f.Add([]byte(""))

	f.Fuzz(func(t *testing.T, raw []byte) {
		// Empty containRoot: the fuzzer supplies only the top file's bytes, so no
		// include is followed — the fuzz target exercises the line parser, and the
		// include-following path is covered by TestRequirementsFollowsIncludes.
		g, err := parseRequirements("requirements.txt", raw, "requirements.txt", "")
		if err != nil {
			return
		}
		if g == nil {
			t.Fatal("nil graph with nil error")
		}
		_ = g.Coverage()
		_ = g.Orphans()
	})
}

// FuzzParsePipfileLock drives arbitrary bytes at the Pipfile.lock JSON parser.
func FuzzParsePipfileLock(f *testing.F) {
	f.Add([]byte(`{"default":{"flask":{"version":"==2.0.1"}}}`))
	f.Add([]byte(`{"default":{"a":{"version":""}},"develop":{"b":{"version":"==1"}}}`))
	f.Add([]byte(`{"_meta":{},"default":null}`))
	f.Add([]byte(`{}`))

	f.Fuzz(func(t *testing.T, raw []byte) {
		g, err := parsePipfileLock("Pipfile.lock", raw)
		if err != nil {
			return
		}
		if g == nil {
			t.Fatal("nil graph with nil error")
		}
		_ = g.Coverage()
	})
}

// FuzzExtractFromTar drives arbitrary bytes at the sdist tar reader. This is the
// one parser that consumes remote attacker-controlled archive bytes, so its
// hostile-input bounds (F-05) must hold under mutation, not merely against the
// hand-written bomb fixtures.
func FuzzExtractFromTar(f *testing.F) {
	f.Add([]byte(""))
	f.Add(tarSeed("pkg-1.0/setup.py", "import os"))
	f.Add(tarSeed("pkg-1.0/pyproject.toml", "[build-system]"))
	f.Add(tarSeed("pkg-1.0/sub/evil.pth", "import evil"))
	f.Add(tarSeed("../escape/setup.py", "x"))

	f.Fuzz(func(t *testing.T, raw []byte) {
		files, err := extractFromTar(bytes.NewReader(raw))
		if err != nil {
			return
		}
		if files == nil {
			t.Fatal("nil files with nil error")
		}
		// The retention caps must hold no matter what the archive claimed.
		if len(files.PthFiles) > maxPthFiles {
			t.Fatalf("retained %d .pth files, cap is %d", len(files.PthFiles), maxPthFiles)
		}
		var total int64
		for _, c := range files.PthFiles {
			total += int64(len(c))
		}
		if total > maxPthTotalBytes {
			t.Fatalf("retained %d .pth bytes, cap is %d", total, maxPthTotalBytes)
		}
		if int64(len(files.SetupPy)) > maxFileSize || int64(len(files.PyprojectToml)) > maxFileSize {
			t.Fatal("per-file cap exceeded")
		}
	})
}
