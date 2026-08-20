package registry

import "testing"

// parseCargoDeps must record the dependency KIND (normal/build), keep build and
// normal, and drop dev — the substrate the yank-lure build-dep diff reads (OPU-26).
func TestParseCargoDepsRecordsKind(t *testing.T) {
	raw := `{"dependencies":[
		{"crate_id":"proc-macro1","req":"^1.0","kind":"build","optional":false},
		{"crate_id":"serde","req":"^1.0","kind":"normal","optional":false},
		{"crate_id":"quickcheck","req":"^0.6","kind":"dev","optional":false},
		{"crate_id":"plainly","req":"^2.0","optional":false}
	]}`
	reqs, _, err := parseCargoDeps([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, r := range reqs {
		got[r.Name] = r.Kind
	}
	if _, ok := got["quickcheck"]; ok {
		t.Error("dev dependency must be dropped")
	}
	if got["proc-macro1"] != "build" {
		t.Errorf("proc-macro1 kind = %q, want build", got["proc-macro1"])
	}
	if got["serde"] != "normal" {
		t.Errorf("serde kind = %q, want normal", got["serde"])
	}
	if got["plainly"] != "normal" {
		t.Errorf("kind-less dep defaults to %q, want normal", got["plainly"])
	}
}

// IntroducedBuildDeps returns only BUILD deps present in newest but not baseline —
// the arrayref tell (0.3.10 added proc-macro1 as a build dep 0.3.9 lacked), and
// nothing else: a new NORMAL dep, or a build dep already present, is not it.
func TestIntroducedBuildDeps(t *testing.T) {
	baseline := []CargoRequirement{
		{Name: "cc", Kind: "build"},     // already a build dep
		{Name: "serde", Kind: "normal"}, // normal
	}
	newest := []CargoRequirement{
		{Name: "cc", Kind: "build"},          // unchanged build dep — not introduced
		{Name: "serde", Kind: "normal"},      // unchanged
		{Name: "proc-macro1", Kind: "build"}, // NEW build dep — the tell
		{Name: "regex", Kind: "normal"},      // new but NORMAL — ignored
	}
	got := IntroducedBuildDeps(baseline, newest)
	if len(got) != 1 || got[0] != "proc-macro1" {
		t.Errorf("IntroducedBuildDeps = %v, want [proc-macro1]", got)
	}
	// Symmetry check: nothing new => empty.
	if len(IntroducedBuildDeps(newest, newest)) != 0 {
		t.Error("identical dep sets must introduce nothing")
	}
}
