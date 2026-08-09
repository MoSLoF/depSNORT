package purl

import "testing"

func TestNewNpmString(t *testing.T) {
	cases := []struct {
		name, version, want string
	}{
		{"express", "4.19.2", "pkg:npm/express@4.19.2"},
		{"@scope/util", "2.0.1", "pkg:npm/%40scope/util@2.0.1"},
		{"lodash", "4.17.21", "pkg:npm/lodash@4.17.21"},
	}
	for _, c := range cases {
		got := NewNpm(c.name, c.version).String()
		if got != c.want {
			t.Errorf("NewNpm(%q,%q).String() = %q, want %q", c.name, c.version, got, c.want)
		}
	}
}

func TestParseRoundTrip(t *testing.T) {
	for _, s := range []string{
		"pkg:npm/express@4.19.2",
		"pkg:npm/%40scope/util@2.0.1",
	} {
		p, err := Parse(s)
		if err != nil {
			t.Fatalf("Parse(%q) error: %v", s, err)
		}
		if got := p.String(); got != s {
			t.Errorf("round-trip %q -> %q", s, got)
		}
	}
}

func TestParseScopeDecoded(t *testing.T) {
	p, err := Parse("pkg:npm/%40scope/util@2.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if p.Namespace != "@scope" || p.Name != "util" || p.Version != "2.0.1" {
		t.Errorf("got %+v", p)
	}
}

func TestParseErrors(t *testing.T) {
	for _, s := range []string{"express@1.0.0", "pkg:npm", "pkg:/name"} {
		if _, err := Parse(s); err == nil {
			t.Errorf("Parse(%q) expected error, got nil", s)
		}
	}
}
