package pep508

import "testing"

func TestSplit(t *testing.T) {
	cases := []struct {
		in                    string
		name, version, marker string
		pinned                bool
	}{
		{"flask==2.0.1", "flask", "2.0.1", "", true},
		{"Flask_SQLAlchemy[async]==2.5.1", "Flask_SQLAlchemy", "2.5.1", "", true},
		{`requests==2.31.0 ; python_version >= "3.8"`, "requests", "2.31.0", `python_version >= "3.8"`, true},
		{"pkg==1.0.*", "pkg", "1.0", "", true},
		{"urllib3>=1.21.1", "urllib3", "", "", false},
		{"some-package", "some-package", "", "", false},
		{`pyreadline3 ; sys_platform == "win32"`, "pyreadline3", "", `sys_platform == "win32"`, false},
		{"pkg[extra]>=1.0", "pkg", "", "", false},
		// PyPI JSON API's legacy PEP 345-style requires_dist form.
		{"Werkzeug (>=2.0)", "Werkzeug", "", "", false},
		{"foo (==1.2.3)", "foo", "1.2.3", "", true},
		{"foo (>=1.0,<2.0)", "foo", "", "", false},
		{`asgiref (>=3.2) ; extra == "async"`, "asgiref", "", `extra == "async"`, false},
		{"foo[extra] (>=1.0)", "foo", "", "", false},
	}
	for _, c := range cases {
		name, version, pinned, marker := Split(c.in)
		if name != c.name || version != c.version || pinned != c.pinned || marker != c.marker {
			t.Errorf("Split(%q) = (%q, %q, %v, %q), want (%q, %q, %v, %q)",
				c.in, name, version, pinned, marker, c.name, c.version, c.pinned, c.marker)
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
