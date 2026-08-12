package purl

import "testing"

// D-33, found by FuzzParse. Node identity across the whole tool IS the PURL
// string: the graph dedupes on it, IOC ledger entries key on it, and cross-repo
// blast radius is computed by merging equal ones. So two properties have to
// hold, and neither did before.

// 1. Normalization must be a fixed point. Parse->String used to consume a
// trailing "@" that String never re-emitted, so each pass silently dropped a
// character and one package could normalize to a succession of identities.
func TestParseStringIsStable(t *testing.T) {
	for _, s := range []string{
		"pkg:npm/lodash@4.17.21",
		"pkg:npm/%40scope/pkg@1.2.3",
		"pkg:npm/@@@@@@@",
		"pkg:npm/a@",
		"pkg:pypi/flask@2.0.1",
		"pkg:composer/vendor/pkg@1.0",
	} {
		p, err := Parse(s)
		if err != nil {
			continue // refusing to parse is fine; drifting is not
		}
		once := p.String()
		p2, err := Parse(once)
		if err != nil {
			t.Fatalf("Parse(%q) -> %q, which no longer parses: %v", s, once, err)
		}
		if twice := p2.String(); twice != once {
			t.Errorf("normalization drifts: %q -> %q -> %q", s, once, twice)
		}
	}
}

// 2. A component must not be able to forge PURL structure. A package name
// carrying "@" would otherwise render an extra version separator, letting a
// hostile lockfile mint an identity that collides with a real package — or slips
// past an IOC ledger entry keyed on that package's PURL.
func TestCraftedNameCannotForgeVersionSeparator(t *testing.T) {
	real := NewNpm("lodash", "4.17.21")
	// A package literally NAMED "lodash@4.17.21", declaring no version.
	impostor := NewNpm("lodash@4.17.21", "")

	if real.String() == impostor.String() {
		t.Fatalf("identity collision: a package named %q renders the same PURL as the real %s",
			"lodash@4.17.21", real.String())
	}
	if real.String() != "pkg:npm/lodash@4.17.21" {
		t.Errorf("canonical form for a real package changed: %s", real.String())
	}

	// And the impostor must survive a round trip as its own distinct identity.
	back, err := Parse(impostor.String())
	if err != nil {
		t.Fatalf("impostor PURL %q does not parse: %v", impostor.String(), err)
	}
	if back.Name != "lodash@4.17.21" || back.Version != "" {
		t.Errorf("round trip lost the crafted name: got name=%q version=%q", back.Name, back.Version)
	}
}

// A "/" in a name must not be able to forge an extra namespace segment either.
func TestCraftedNameCannotForgeNamespace(t *testing.T) {
	p := NewGem("evil/../escape", "1.0")
	back, err := Parse(p.String())
	if err != nil {
		t.Fatalf("%q does not parse: %v", p.String(), err)
	}
	if back.Name != "evil/../escape" || back.Namespace != "" {
		t.Errorf("name forged a namespace: name=%q namespace=%q", back.Name, back.Namespace)
	}
}

// An invalid type is structural garbage, not a package.
func TestInvalidTypeRejected(t *testing.T) {
	for _, s := range []string{"pkg:0@/@", "pkg:np@m/a@1", "pkg:1npm/a@1", "pkg:/a@1"} {
		if p, err := Parse(s); err == nil {
			t.Errorf("Parse(%q) should fail, got %+v", s, p)
		}
	}
}
