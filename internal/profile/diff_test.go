package profile

import (
	"reflect"
	"testing"

	"ihbv.io/depsnort/internal/datasource"
	"ihbv.io/depsnort/internal/graph"
	"ihbv.io/depsnort/internal/semver"
)

func prof(version string, caps, hooks []string) Profile {
	return Profile{
		Schema: Schema, PURL: "pkg:npm/acme-widget@" + version,
		Ecosystem: "npm", Name: "acme-widget", Version: version,
		Caps: caps, Hooks: hooks,
	}
}

func TestDiffNoChange(t *testing.T) {
	base := prof("1.2.3", []string{"exec"}, []string{"postinstall"})
	same := prof("1.2.3", []string{"exec"}, []string{"postinstall"})

	d := Diff(base, same)
	if d.HasChange() {
		t.Errorf("identical profiles reported drift: %+v", d)
	}
	if d.Bump != semver.BumpNone {
		t.Errorf("Bump = %q, want %q", d.Bump, semver.BumpNone)
	}
}

func TestDiffCapabilityAdditionAndRemoval(t *testing.T) {
	base := prof("1.2.3", []string{"exec"}, []string{"postinstall"})
	next := prof("1.2.4", []string{"exec", "network", "credentials"}, []string{"postinstall", "preinstall"})

	d := Diff(base, next)
	if want := []string{"credentials", "network"}; !reflect.DeepEqual(d.AddedCaps, want) {
		t.Errorf("AddedCaps = %v, want %v (sorted)", d.AddedCaps, want)
	}
	if want := []string{"preinstall"}; !reflect.DeepEqual(d.AddedHooks, want) {
		t.Errorf("AddedHooks = %v, want %v", d.AddedHooks, want)
	}
	if d.Bump != semver.BumpPatch {
		t.Errorf("Bump = %q, want patch — the weight VC-010 hangs on", d.Bump)
	}
	if !d.Escalating() {
		t.Error("adding capabilities must be Escalating()")
	}

	// The reverse direction: a release that DROPS a hook has drifted, but not
	// in a direction that should draw attention.
	back := Diff(next, base)
	if !back.HasChange() {
		t.Error("dropping capabilities is still a change")
	}
	if back.Escalating() {
		t.Error("removing capabilities must not count as escalation")
	}
	if want := []string{"credentials", "network"}; !reflect.DeepEqual(back.RemovedCaps, want) {
		t.Errorf("RemovedCaps = %v, want %v", back.RemovedCaps, want)
	}
}

func TestDiffPublisherRequiresBothSides(t *testing.T) {
	withPub := func(p Profile, key string) Profile {
		p.Publisher = datasource.Publisher{ID: key, Name: key, Source: "npm._npmUser"}
		return p
	}
	base := withPub(prof("1.2.3", nil, nil), "alice")

	t.Run("changed", func(t *testing.T) {
		d := Diff(base, withPub(prof("1.2.4", nil, nil), "mallory"))
		if !d.PublisherChanged || d.PublisherUnknown {
			t.Errorf("want PublisherChanged, got %+v", d)
		}
		if d.FromPublisher != "alice" || d.ToPublisher != "mallory" {
			t.Errorf("publishers = %q -> %q", d.FromPublisher, d.ToPublisher)
		}
	})

	t.Run("same", func(t *testing.T) {
		d := Diff(base, withPub(prof("1.2.4", nil, nil), "alice"))
		if d.PublisherChanged || d.PublisherUnknown {
			t.Errorf("want no publisher signal, got %+v", d)
		}
	})

	// The case the model must never get wrong: one side has no identity. That
	// is unevaluable, not "the same publisher" (D-40).
	t.Run("unknown on one side", func(t *testing.T) {
		d := Diff(base, prof("1.2.4", nil, nil))
		if d.PublisherChanged {
			t.Error("a missing identity must never be reported as a publisher change")
		}
		if !d.PublisherUnknown {
			t.Error("a missing identity must be reported as unknown, not silently dropped")
		}
	})
}

func TestDiffSourceClassChange(t *testing.T) {
	base := prof("1.2.3", nil, nil)
	base.SourceClass = graph.SourceRegistry
	next := prof("1.2.4", nil, nil)
	next.SourceClass = graph.SourceGit

	d := Diff(base, next)
	if !d.SourceClassChanged || d.FromSourceClass != graph.SourceRegistry || d.ToSourceClass != graph.SourceGit {
		t.Errorf("want registry->git recorded, got %+v", d)
	}
	if !d.HasChange() {
		t.Error("a dependency repointed at a fork is a change even with identical capabilities")
	}

	// An unrecorded class on either side is not a transition.
	bare := prof("1.2.4", nil, nil)
	if d := Diff(base, bare); d.SourceClassChanged {
		t.Error("missing provenance on one side must not report a source-class change")
	}
}

func TestDiffCarriesUnobservableFromBothSides(t *testing.T) {
	base := prof("1.2.3", nil, nil)
	base.Unobserved = []string{UnobservedPublisher}
	next := prof("1.2.4", nil, nil)
	next.Unobserved = []string{UnobservedInstallSurface, UnobservedPublisher}

	d := Diff(base, next)
	want := []string{UnobservedInstallSurface, UnobservedPublisher}
	if !reflect.DeepEqual(d.Unobservable, want) {
		t.Errorf("Unobservable = %v, want %v (deduplicated union, sorted)", d.Unobservable, want)
	}
}

func TestDiffBumpKinds(t *testing.T) {
	tests := []struct {
		from, to string
		want     semver.Bump
	}{
		{"1.2.3", "1.2.4", semver.BumpPatch},
		{"1.2.3", "1.3.0", semver.BumpMinor},
		{"1.2.3", "2.0.0", semver.BumpMajor},
		{"1.2.3", "1.2.3", semver.BumpNone},
		{"not-a-version", "1.2.4", semver.BumpUnknown},
	}
	for _, tt := range tests {
		if got := Diff(prof(tt.from, nil, nil), prof(tt.to, nil, nil)).Bump; got != tt.want {
			t.Errorf("Diff(%s -> %s).Bump = %q, want %q", tt.from, tt.to, got, tt.want)
		}
	}
}

func TestDiffRemoteHostsAndSinks(t *testing.T) {
	base := prof("1.2.3", nil, nil)
	base.RemoteHosts = []string{"cdn.example.invalid"}
	next := prof("1.2.4", nil, nil)
	next.RemoteHosts = []string{"cdn.example.invalid", "collector.example.invalid"}
	next.Sinks = []string{"NPM_TOKEN"}

	d := Diff(base, next)
	if want := []string{"collector.example.invalid"}; !reflect.DeepEqual(d.AddedRemoteHosts, want) {
		t.Errorf("AddedRemoteHosts = %v, want %v", d.AddedRemoteHosts, want)
	}
	if want := []string{"NPM_TOKEN"}; !reflect.DeepEqual(d.AddedSinks, want) {
		t.Errorf("AddedSinks = %v, want %v", d.AddedSinks, want)
	}
}
