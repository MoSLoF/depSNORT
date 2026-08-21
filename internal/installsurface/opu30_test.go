package installsurface

import "testing"

// OPU-30: IsKnownBuildBackend must match the backend MODULE exactly. A prefix
// match let an attacker name a malicious backend with a known prefix and be
// trusted (no hook, no coverage gap). These cases lock the exact-match behavior.
func TestIsKnownBuildBackendExactMatch(t *testing.T) {
	known := []string{
		"setuptools.build_meta",
		"setuptools.build_meta:__legacy__", // object suffix stripped -> module known
		"hatchling.build",
		"flit_core.buildapi",
		"poetry.core.masonry.api",
		"pdm.backend",
		"maturin",
		"uv_build",
	}
	for _, b := range known {
		if !IsKnownBuildBackend(b) {
			t.Errorf("expected %q to be KNOWN", b)
		}
	}

	// Prefix spoofs that the old HasPrefix match trusted — must now be UNKNOWN.
	spoofs := []string{
		"hatchling.build_evil",
		"hatchling.build_evil:run",
		"hatchling.build.evil_submodule",
		"setuptools.build_meta_pwn",
		"uv_build_evil",
		"nothatchling.build", // non-matching prefix, always was unknown
	}
	for _, b := range spoofs {
		if IsKnownBuildBackend(b) {
			t.Errorf("SPOOF %q must NOT be treated as a known backend", b)
		}
	}
}
