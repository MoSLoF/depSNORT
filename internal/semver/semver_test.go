package semver

import "testing"

func TestParse(t *testing.T) {
	cases := []struct {
		in            string
		maj, min, pat int
		pre           string
		valid         bool
	}{
		{"1.2.3", 1, 2, 3, "", true},
		{"v4.19.2", 4, 19, 2, "", true},
		{"1.0.0-beta.1", 1, 0, 0, "beta.1", true},
		{"1.0.0+build5", 1, 0, 0, "", true},
		{"latest", 0, 0, 0, "", false},
		{"1.2", 0, 0, 0, "", false},
		{"", 0, 0, 0, "", false},
	}
	for _, c := range cases {
		v := Parse(c.in)
		if v.Valid != c.valid {
			t.Errorf("Parse(%q).Valid = %v, want %v", c.in, v.Valid, c.valid)
			continue
		}
		if !c.valid {
			continue
		}
		if v.Major != c.maj || v.Minor != c.min || v.Patch != c.pat || v.Prerelease != c.pre {
			t.Errorf("Parse(%q) = %+v", c.in, v)
		}
	}
}

func TestBumpKind(t *testing.T) {
	cases := []struct {
		a, b string
		want Bump
	}{
		{"1.2.3", "1.2.4", BumpPatch},
		{"1.2.3", "1.3.0", BumpMinor},
		{"1.2.3", "2.0.0", BumpMajor},
		{"1.2.3", "1.2.3", BumpNone},
		{"latest", "1.2.3", BumpUnknown},
	}
	for _, c := range cases {
		if got := BumpKind(Parse(c.a), Parse(c.b)); got != c.want {
			t.Errorf("BumpKind(%q,%q) = %q, want %q", c.a, c.b, got, c.want)
		}
	}
}

func TestCompare(t *testing.T) {
	if Parse("1.2.3").Compare(Parse("1.2.4")) != -1 {
		t.Error("1.2.3 should sort before 1.2.4")
	}
	if Parse("1.0.0").Compare(Parse("1.0.0-beta")) != 1 {
		t.Error("release should sort after its prerelease")
	}
	if Parse("2.0.0").Compare(Parse("2.0.0")) != 0 {
		t.Error("equal versions should compare 0")
	}
}
