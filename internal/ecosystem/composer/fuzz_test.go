package composer

import (
	"encoding/json"
	"testing"
)

// FuzzParseComposerLock drives arbitrary bytes at the composer.lock parser.
func FuzzParseComposerLock(f *testing.F) {
	f.Add([]byte(`{"packages":[{"name":"a/b","version":"1.0.0"}]}`))
	f.Add([]byte(`{"packages":[{"name":"a/b","version":"1.0","require":{"c/d":"^1"}}],"packages-dev":[]}`))
	f.Add([]byte(`{"packages":[{"name":"../escape","version":"1"}]}`))
	f.Add([]byte(`{"packages":[{"name":"","version":""}]}`))
	f.Add([]byte(`{"packages":null}`))
	f.Add([]byte(`{}`))

	f.Fuzz(func(t *testing.T, raw []byte) {
		g, err := parseComposerLock("composer.lock", raw)
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

// FuzzFlattenScripts drives the composer.json "scripts" normalizer, whose values
// may each be a bare string or an array of strings — a polymorphic JSON shape,
// which is where unmarshal assumptions break.
func FuzzFlattenScripts(f *testing.F) {
	f.Add([]byte(`{"scripts":{"post-install-cmd":"echo hi"}}`))
	f.Add([]byte(`{"scripts":{"post-install-cmd":["a","b"]}}`))
	f.Add([]byte(`{"scripts":{"x":null,"y":5,"z":{"nested":true}}}`))
	f.Add([]byte(`{"type":"composer-plugin","extra":{"class":"V\\P\\Plugin"},"autoload":{"psr-4":{"V\\P\\":"src/"}}}`))
	f.Add([]byte(`{}`))

	f.Fuzz(func(t *testing.T, raw []byte) {
		var m composerManifest
		if err := json.Unmarshal(raw, &m); err != nil {
			return
		}
		flat := flattenScripts(m.Scripts)
		for k, v := range flat {
			_, _ = k, v
		}
	})
}
