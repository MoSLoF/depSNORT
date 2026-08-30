package pypi

import (
	"bytes"
	"testing"
)

// TestExtractFromTarCollectsRuntimeModules pins that the sdist extractor retains
// a package's runtime .py modules (for VC-002L import-time analysis) while
// excluding setup.py and test/docs trees, and still extracts setup.py itself.
func TestExtractFromTarCollectsRuntimeModules(t *testing.T) {
	tarball := makeTar(t, [][2]string{
		{"pkg-1.0/setup.py", "from setuptools import setup\nsetup()"},
		{"pkg-1.0/pkg/__init__.py", "from . import _client\n"},
		{"pkg-1.0/pkg/_client.py", "import base64\nexec(base64.b64decode('eA=='))\n"},
		{"pkg-1.0/tests/test_x.py", "import base64\nexec(base64.b64decode('eA=='))\n"},
		{"pkg-1.0/docs/conf.py", "project = 'x'\n"},
		{"pkg-1.0/README.md", "hi"},
	})
	files, err := extractFromTar(bytes.NewReader(tarball))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"pkg/__init__.py", "pkg/_client.py"} {
		if _, ok := files.Modules[want]; !ok {
			t.Errorf("runtime module %q must be retained; got %v", want, keys(files.Modules))
		}
	}
	for _, dont := range []string{"tests/test_x.py", "docs/conf.py", "setup.py"} {
		if _, ok := files.Modules[dont]; ok {
			t.Errorf("%q must NOT be collected as a runtime module", dont)
		}
	}
	if files.SetupPy == "" {
		t.Error("setup.py must still be extracted as an install hook")
	}
}

// TestModuleRetentionCapDisclosed pins that exceeding the module retention cap
// sets ModulesTruncated (partial disclosed coverage), never a silent drop.
func TestModuleRetentionCapDisclosed(t *testing.T) {
	defer func(n int) { maxModuleFiles = n }(maxModuleFiles)
	maxModuleFiles = 2

	tarball := makeTar(t, [][2]string{
		{"pkg-1.0/pkg/a.py", "x = 1\n"},
		{"pkg-1.0/pkg/b.py", "x = 1\n"},
		{"pkg-1.0/pkg/c.py", "x = 1\n"},
	})
	files, err := extractFromTar(bytes.NewReader(tarball))
	if err != nil {
		t.Fatal(err)
	}
	if !files.ModulesTruncated {
		t.Error("exceeding the module cap must set ModulesTruncated")
	}
	if len(files.Modules) > 2 {
		t.Errorf("retained %d modules, cap was 2", len(files.Modules))
	}
}

func keys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
