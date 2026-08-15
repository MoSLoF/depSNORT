package pep508

import (
	"regexp"
	"strings"
	"testing"
)

func TestSplit(t *testing.T) {
	cases := []struct {
		in                    string
		name, version, marker string
		pinned                bool
	}{
		// --- pre-existing assertions, byte-identical ---
		{"flask==2.0.1", "flask", "2.0.1", "", true},
		{"Flask_SQLAlchemy[async]==2.5.1", "Flask_SQLAlchemy", "2.5.1", "", true},
		{`requests==2.31.0 ; python_version >= "3.8"`, "requests", "2.31.0", `python_version >= "3.8"`, true},
		{"pkg==1.0.*", "pkg", "1.0", "", true},
		{"urllib3>=1.21.1", "urllib3", "", "", false},
		{"some-package", "some-package", "", "", false},
		{`pyreadline3 ; sys_platform == "win32"`, "pyreadline3", "", `sys_platform == "win32"`, false},
		{"pkg[extra]>=1.0", "pkg", "", "", false},
		{"Werkzeug (>=2.0)", "Werkzeug", "", "", false},
		{"foo (==1.2.3)", "foo", "1.2.3", "", true},
		{"foo (>=1.0,<2.0)", "foo", "", "", false},
		{`asgiref (>=3.2) ; extra == "async"`, "asgiref", "", `extra == "async"`, false},
		{"foo[extra] (>=1.0)", "foo", "", "", false},

		// --- the reported bug: real requests requires_dist metadata ---
		// These four are verbatim entries from requests' published PyPI
		// metadata. Pre-fix the three compound ones returned corrupted names
		// ("idna<4," etc.); certifi was the single-clause control that worked.
		{"charset_normalizer<4,>=2", "charset_normalizer", "", "", false},
		{"idna<4,>=2.5", "idna", "", "", false},
		{"urllib3<3,>=1.26", "urllib3", "", "", false},
		{"certifi>=2017.4.17", "certifi", "", "", false},

		// --- root cause #2: a compound is a RANGE, never a pin (D-01) ---
		{"foo==1.0,!=1.0.1", "foo", "", "", false},
		{"foo>=1.0,==1.2", "foo", "", "", false},
		{"foo==1.0.*,!=1.0.1", "foo", "", "", false},
		{"foo<=2.0,>=1.0", "foo", "", "", false},
		{"zope.interface>=5,<6", "zope.interface", "", "", false},

		// --- root cause #3: PEP 440 arbitrary equality is UNPINNED ---
		{"foo===1.0", "foo", "", "", false},
		{"foo === 1.0", "foo", "", "", false},
		{"foo====1.0", "foo", "", "", false},

		// --- extras: the idx[1] vs idx[3] slicing trap ---
		// Slicing rest from the name submatch would leave "[a,b]==1.0", whose
		// comma trips the compound rule and silently downgrades a real pin.
		{"foo[a,b]==1.0", "foo", "1.0", "", true},
		{"foo[a,b]>=1,<2", "foo", "", "", false},
		{"foo[]", "foo", "", "", false},
		{"foo [ a ] >= 1.0", "foo", "", "", false},
		{"a[b]==1", "a", "1", "", true},

		// --- direct references whose URL contains operator characters ---
		{"foo @ git+ssh://git@host/x", "foo", "", "", false},
		{"foo@https://h/p?a=1&b<2", "foo", "", "", false},
		{"foo @ https://h/p?a=1,2", "foo", "", "", false},
		{"foo[a] @ https://h/x", "foo", "", "", false},

		// --- F-B: an accepted "==" version must be a plausible version ---
		{"foo==1.0 bar", "foo", "", "", false},
		{"foo== =1.0", "foo", "", "", false},
		{"foo==>1.0", "foo", "", "", false},
		{"foo==1.0)", "foo", "", "", false},
		{"foo==1.0#egg=x", "foo", "", "", false},
		{"foo==1.0[a]", "foo", "", "", false},
		{"foo==1.*.*", "foo", "", "", false},
		{"foo==", "foo", "", "", false},
		{"foo==.*", "foo", "", "", false},
		{"foo==1.*", "foo", "1", "", true},
		{"foo==1!2.0", "foo", "1!2.0", "", true},
		{"foo==1.0+local", "foo", "1.0+local", "", true},
		{"foo==1.0rc1", "foo", "1.0rc1", "", true},

		// --- F-A: a UTF-8 BOM must not delete the first dependency ---
		{utf8BOM + "requests==2.31.0", "requests", "2.31.0", "", true},
		{utf8BOM + "urllib3<3,>=1.26", "urllib3", "", "", false},

		// --- grammar violations and non-requirements -> visible absence ---
		{"https://files.pythonhosted.org/x/foo-1.0.tar.gz", "", "", "", false},
		{"git+https://github.com/x/y.git#egg=foo", "", "", "", false},
		{"./local/pkg", "", "", "", false},
		{"/abs/path", "", "", "", false},
		{"file:///tmp/x", "", "", "", false},
		{"foo bar", "", "", "", false},
		{"foo 1.0", "", "", "", false},
		{"-foo", "", "", "", false},
		{".foo", "", "", "", false},
		{"foo-", "", "", "", false},
		{"foo.", "", "", "", false},
		{"foo_", "", "", "", false},
		{"==1.0", "", "", "", false},
		{">=1.0", "", "", "", false},
		{"@url", "", "", "", false},
		{"", "", "", "", false},
		{",", "", "", "", false},
		{"[]", "", "", "", false},
		{".", "", "", "", false},
		{"foo[a,b>=1", "", "", "", false},
		{"Flask–SQLAlchemy==1.0", "", "", "", false}, // EN DASH, not a hyphen

		// --- whitespace shapes ---
		{" flask==2.0.1", "flask", "2.0.1", "", true},
		{"foo (==1.2.3) ", "foo", "1.2.3", "", true},
		{"foo == 1.0", "foo", "1.0", "", true},
		{"foo ==1.0", "foo", "1.0", "", true},
		{"foo== 1.0", "foo", "1.0", "", true},
		{"  foo  [ a ]  >=  1 , < 2  ", "foo", "", "", false},

		// --- markers ---
		{"foo>=1,<2 ; python_version<'3.9'", "foo", "", "python_version<'3.9'", false},
		{"numpy>=1.21.0,<2.0.0; python_version>='3.9'", "numpy", "", "python_version>='3.9'", false},
		{"foo;marker", "foo", "", "marker", false},
		{"foo;", "foo", "", "", false},
		{";marker", "", "", "marker", false},

		// --- plain names ---
		{"foo", "foo", "", "", false},
		{"foo-bar", "foo-bar", "", "", false},
		{"foo.bar", "foo.bar", "", "", false},
		{"foo_bar", "foo_bar", "", "", false},
		{"a", "a", "", "", false},
	}
	for _, c := range cases {
		name, version, pinned, marker := Split(c.in)
		if name != c.name || version != c.version || pinned != c.pinned || marker != c.marker {
			t.Errorf("Split(%q) = (%q, %q, %v, %q), want (%q, %q, %v, %q)",
				c.in, name, version, pinned, marker, c.name, c.version, c.pinned, c.marker)
		}
	}
}

// corpus is every input TestSplit exercises, plus adversarial shapes that only
// matter to the invariants below. The invariant tests run over all of it.
var corpus = []string{
	"flask==2.0.1", "Flask_SQLAlchemy[async]==2.5.1", "pkg==1.0.*",
	"charset_normalizer<4,>=2", "idna<4,>=2.5", "urllib3<3,>=1.26",
	"certifi>=2017.4.17", "foo==1.0,!=1.0.1", "foo>=1.0,==1.2",
	"foo==1.0.*,!=1.0.1", "foo<=2.0,>=1.0", "zope.interface>=5,<6",
	"foo===1.0", "foo====1.0", "foo[a,b]==1.0", "foo[a,b]>=1,<2",
	"foo @ git+ssh://git@host/x", "foo@https://h/p?a=1&b<2",
	"foo @ https://h/p?a=1,2", "foo==1.0 bar", "foo==>1.0", "foo==1.0#egg=x",
	"foo==1.0[a]", "foo==", "foo==.*", "foo==1.*",
	utf8BOM + "requests==2.31.0", utf8BOM + "urllib3<3,>=1.26",
	"https://files.pythonhosted.org/x/foo-1.0.tar.gz",
	"git+https://github.com/x/y.git#egg=foo", "./local/pkg", "C:\\foo\\bar",
	"foo bar", "-foo", ".foo", "foo-", "==1.0", "", ",", "[]",
	"foo[a,b>=1", "foo[a[b]]==1.0", "foo[", "foo]", "foo[a] [b]==1",
	"foo (>=1.0,<2.0)", "foo[a] (>=1,<2)", "foo ()", "(foo)",
	"foo (>=1.0)extra", "foo==1.0 (bar)", "foo (==1.2.3) ",
	"foo>=1,<2 ; python_version<'3.9'", "foo;marker", ";marker",
	`foo==1.0 ; extra == "a;b"`, "foo @ https://h/p;extra_info=1",
	"Flask–SQLAlchemy==1.0", "foo\u00a0==1.0", "  foo  [ a ]  >=  1 , < 2  ",
	"foo..bar", "foo--bar", "foo__bar", "a", "1.0",
	"requests-2.31.0-py3-none-any.whl", "numpy-1.9.2.tar.gz",
	strings.Repeat("a", 4096) + "==1.0",
}

// TestSplitNameNeverContainsSpecifierSyntax is the standing guard against the
// entire bug category this parser fix closed. It is deliberately written as a
// literal blacklist, INDEPENDENT of nameAndExtrasRe: asserting the name matches
// the pattern it was sliced from would be tautological and could not fail.
func TestSplitNameNeverContainsSpecifierSyntax(t *testing.T) {
	bad := regexp.MustCompile(`[<>=!~@,()\[\]:/\s]`)
	for _, in := range corpus {
		name, _, _, _ := Split(in)
		if name == "" {
			continue
		}
		if bad.MatchString(name) {
			t.Errorf("Split(%q) returned name %q containing specifier syntax", in, name)
		}
	}
}

// TestSplitNeverPinsCompoundSpecifier locks root cause #2: a comma-joined
// specifier is a range, so it must never come back as an exact pin no matter
// which clause contains "==" (D-01).
func TestSplitNeverPinsCompoundSpecifier(t *testing.T) {
	for _, in := range corpus {
		// Only consider the specifier, not an extras group or a marker.
		body := in
		if i := strings.IndexByte(body, ';'); i >= 0 {
			body = body[:i]
		}
		name, version, pinned, _ := Split(body)
		if name == "" {
			continue
		}
		rest := strings.TrimPrefix(body, name)
		if i := strings.IndexByte(rest, ']'); i >= 0 {
			rest = rest[i+1:] // drop the extras group
		}
		if !strings.Contains(rest, ",") {
			continue
		}
		if pinned || version != "" {
			t.Errorf("Split(%q) = version %q, pinned %v; a compound specifier must never pin",
				body, version, pinned)
		}
	}
}

// TestSplitPinnedVersionIsWellFormed guards F-B: anything reported as an exact
// pin becomes a graph node identity via purl.NewPyPI, so it must never carry
// whitespace, an operator, or other syntax that would mint a malformed PURL.
func TestSplitPinnedVersionIsWellFormed(t *testing.T) {
	bad := regexp.MustCompile(`[<>=!~@,()\[\]#*\s]`)
	for _, in := range corpus {
		_, version, pinned, _ := Split(in)
		if !pinned {
			if version != "" {
				t.Errorf("Split(%q) unpinned but returned version %q", in, version)
			}
			continue
		}
		if version == "" {
			t.Errorf("Split(%q) pinned with an empty version", in)
		}
		if bad.MatchString(version) {
			t.Errorf("Split(%q) pinned version %q contains malformed syntax", in, version)
		}
	}
}

func TestStripExtras(t *testing.T) {
	cases := map[string]string{
		"requests[security]": "requests",
		"requests":           "requests",
		" flask [async] ":    "flask",
	}
	for in, want := range cases {
		if got := StripExtras(in); got != want {
			t.Errorf("StripExtras(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestExcludesLinux(t *testing.T) {
	cases := map[string]bool{
		`sys_platform=='win32'`:                true,
		`sys_platform == 'win32'`:              true,
		`sys_platform=="win32"`:                true,
		`os_name=='nt'`:                        true,
		`platform_system=='Windows'`:           true,
		`platform_system == "Windows"`:         true,
		`python_version < '3.9'`:               false,
		`sys_platform=='win32' and extra=='x'`: false,
		``:                                     false,
	}
	for marker, want := range cases {
		if got := ExcludesLinux(marker); got != want {
			t.Errorf("ExcludesLinux(%q) = %v, want %v", marker, got, want)
		}
	}
}

func TestGatedByExtra(t *testing.T) {
	cases := map[string]bool{
		`extra == "async"`:        true,
		`extra=='security'`:       true,
		`python_version >= "3.8"`: false,
		`sys_platform=='win32'`:   false,
		``:                        false,
	}
	for marker, want := range cases {
		if got := GatedByExtra(marker); got != want {
			t.Errorf("GatedByExtra(%q) = %v, want %v", marker, got, want)
		}
	}
}
