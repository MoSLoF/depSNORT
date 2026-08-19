package pep508

import "testing"

// SplitSpecifier must preserve the raw range that Split throws away, and must
// keep Split's disclosure rule: a leading token that is not a legal name never
// masquerades as a package.
func TestSplitSpecifier(t *testing.T) {
	for _, tc := range []struct{ in, name, spec, marker string }{
		{"urllib3>=1.21,<2.0", "urllib3", ">=1.21,<2.0", ""},
		{"flask-sqlalchemy>=3.0", "flask-sqlalchemy", ">=3.0", ""},
		{"requests", "requests", "", ""},
		{"requests[socks]>=2.0", "requests", ">=2.0", ""},
		{"foo (==1.2.3)", "foo", "==1.2.3", ""},
		{`aiohttp ; extra == "async"`, "aiohttp", "", `extra == "async"`},
		{"pywin32 ; sys_platform == \"win32\"", "pywin32", "", `sys_platform == "win32"`},
		{"https://files.pythonhosted.org/x/foo-1.0.tar.gz", "", "", ""},
		{"", "", "", ""},
	} {
		name, spec, marker := SplitSpecifier(tc.in)
		if name != tc.name || spec != tc.spec || marker != tc.marker {
			t.Errorf("SplitSpecifier(%q) = (%q, %q, %q), want (%q, %q, %q)",
				tc.in, name, spec, marker, tc.name, tc.spec, tc.marker)
		}
	}
}

// The two splitters must agree on the name for every input: they share the
// regex, the BOM strip, and the paren-unwrap, and a divergence would mean the
// walk and the re-parenting pass disagree about which package a line names.
func TestSplitAndSplitSpecifierAgreeOnName(t *testing.T) {
	for _, in := range []string{
		"urllib3>=1.21,<2.0", "requests==2.31.0", "foo[a,b]==1.0",
		"pkg ; python_version < '3.9'", "bad url/thing", "\ufeffleading-bom==1.0",
	} {
		n1, _, _, _ := Split(in)
		n2, _, _ := SplitSpecifier(in)
		if n1 != n2 {
			t.Errorf("name disagreement on %q: Split=%q SplitSpecifier=%q", in, n1, n2)
		}
	}
}
