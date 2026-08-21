package pypi

import (
	"testing"

	"ihbv.io/depsnort/internal/graph"
	"ihbv.io/depsnort/internal/installsurface"
)

// The OPU-29 build-backend coverage fix: a standard, unpinned PEP 517 backend is
// disclosed non-gating (pypi.build_backend) and must NOT count as an unresolved
// coverage gap; an unknown backend still gates via AttrUnresolved.
func TestKnownBackendIsNonGating(t *testing.T) {
	// uv_build was added to the known set for uv-managed projects.
	for _, b := range []string{"hatchling.build", "setuptools.build_meta", "pdm.backend", "uv_build"} {
		if !installsurface.IsKnownBuildBackend(b) {
			t.Errorf("expected %q to be a known build backend", b)
		}
	}
	if installsurface.IsKnownBuildBackend("evil_backend.build") {
		t.Error("evil_backend.build must not be treated as known")
	}

	// A known backend routes to the non-gating disclosure, not the coverage gate.
	known := &graph.Node{ID: "pkg:pypi/x@1", Ecosystem: "pypi"}
	addKnownBackend(known, "hatchling")
	if known.Attr[graph.AttrUnresolved] != "" {
		t.Error("known backend must not populate AttrUnresolved")
	}
	if known.Attr["pypi.build_backend"] != "hatchling" {
		t.Errorf("known backend disclosure = %q, want hatchling", known.Attr["pypi.build_backend"])
	}

	// An unknown/unpinned backend still gates coverage.
	unknown := &graph.Node{ID: "pkg:pypi/y@1", Ecosystem: "pypi"}
	addUnresolved(unknown, "sketchy_backend")
	if unknown.Attr[graph.AttrUnresolved] != "sketchy_backend" {
		t.Errorf("unknown backend AttrUnresolved = %q, want sketchy_backend", unknown.Attr[graph.AttrUnresolved])
	}
}
