package main

import "testing"

// TestUseAssertedTier locks in OPU-12 D-2: the deps.dev asserted tier is default
// on, suppressed by -no-depsdev, and impossible under -offline (no network),
// where the walk falls back to presumed versions.
func TestUseAssertedTier(t *testing.T) {
	cases := []struct {
		depsDev, noDepsDev, offline, want bool
	}{
		{true, false, false, true},   // default scan → asserted
		{true, true, false, false},   // -no-depsdev → presumed
		{true, false, true, false},   // -offline → presumed (no network)
		{true, true, true, false},    // both → presumed
		{false, false, false, false}, // explicit -depsdev=false → presumed
	}
	for _, c := range cases {
		if got := useAssertedTier(c.depsDev, c.noDepsDev, c.offline); got != c.want {
			t.Errorf("useAssertedTier(depsDev=%v,noDepsDev=%v,offline=%v) = %v, want %v",
				c.depsDev, c.noDepsDev, c.offline, got, c.want)
		}
	}
	if presumedClosureNote == "" {
		t.Error("presumedClosureNote must be a non-empty in-report caveat")
	}
}
