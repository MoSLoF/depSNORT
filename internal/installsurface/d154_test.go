package installsurface

import "testing"

// D-154/OPU-41: the propagation detector D-152 shipped was npm-only —
// gem push, cargo publish, dotnet/nuget push and the PyPI upload paths all
// scanned as plain [exec] or [network], indistinguishable from an ordinary
// build step, even though CapPropagate and graph.EdgeRepublish were already
// ecosystem-neutral. This is the marker-table extension the D-152
// residual-limitations note called for.

// TestD154NonNpmRegistryPublishIsPropagation: the worm step, in the forms it
// takes outside the npm family.
func TestD154NonNpmRegistryPublishIsPropagation(t *testing.T) {
	for name, src := range map[string]string{
		"rubygems push":       "system('gem push pkg/wormy-1.0.0.gem')",
		"cargo publish":       "cp.execSync('cargo publish --token $CARGO_TOKEN')",
		"dotnet nuget push":   "cp.execSync('dotnet nuget push wormy.1.0.0.nupkg -k $NUGET_KEY -s https://api.nuget.org/v3/index.json')",
		"nuget push (bare)":   "cp.execSync('nuget push wormy.1.0.0.nupkg')",
		"twine upload":        "os.system('twine upload dist/*')",
		"twine via python -m": "os.system('python -m twine upload dist/*')",
		"flit publish":        "cp.execSync('flit publish')",
		"hatch publish":       "cp.execSync('hatch publish')",
		"poetry publish":      "cp.execSync('poetry publish --build')",
	} {
		if !hasCap(d152Caps(t, src), CapPropagate) {
			t.Errorf("%s: expected CapPropagate, got %v", name, d152Caps(t, src))
		}
	}
}

// TestD154CargoDryRunIsNotPropagation mirrors the npm --dry-run boundary
// (D-152) for the one other ecosystem with a confirmed rehearsal flag.
func TestD154CargoDryRunIsNotPropagation(t *testing.T) {
	for _, src := range []string{
		"cp.execSync('cargo publish --dry-run')",
		"cp.execSync('cargo publish --token $T --dry-run')",
	} {
		if hasCap(d152Caps(t, src), CapPropagate) {
			t.Errorf("a cargo --dry-run rehearsal is not propagation: %q -> %v", src, d152Caps(t, src))
		}
	}
}

// TestD154UnrelatedVerbsAreNotPropagation: words that look like the new
// markers but are not a registry publish. "push" and "publish" are both
// common outside a package-manager context (git push, event publish), so the
// verb+manager anchoring has to hold here exactly as it does for npm.
func TestD154UnrelatedVerbsAreNotPropagation(t *testing.T) {
	for name, src := range map[string]string{
		"git push":            "cp.execSync('git push origin main')",
		"git push with force": "cp.execSync('git push --force-with-lease')",
		"docker push":         "cp.execSync('docker push myimage:latest')",
		"kubectl apply":       "cp.execSync('kubectl apply -f deploy.yaml')",
		"bare publish() call": "eventBus.publish('build:done');",
	} {
		if hasCap(d152Caps(t, src), CapPropagate) {
			t.Errorf("%s must not be propagation: %q -> %v", name, src, d152Caps(t, src))
		}
	}
}

// TestD154OrdinaryEcosystemToolingIsUnaffected is the anti-vacuity baseline
// (D-152's own lesson applied here): prove scanCaps still classifies these
// non-npm ecosystems' benign commands, so the absence of CapPropagate above
// means something rather than reflecting a scanner that stopped matching
// anything for these ecosystems.
func TestD154OrdinaryEcosystemToolingIsUnaffected(t *testing.T) {
	for name, src := range map[string]string{
		"cargo build":   "cp.execSync('cargo build --release')",
		"gem install":   "system('gem install bundler')",
		"nuget restore": "cp.execSync('nuget restore')",
		"pip install":   "os.system('pip install -r requirements.txt')",
	} {
		if hasCap(d152Caps(t, src), CapPropagate) {
			t.Errorf("%s must not itself be propagation: %q", name, src)
		}
		if len(d152Caps(t, src)) == 0 {
			t.Errorf("%s: scanCaps classified nothing for %q — negative case is vacuous", name, src)
		}
	}
}

// TestD154EvidenceNamesTheCommand: matches the D-152 evidence-quality
// assertion — a finding has to say WHAT it saw.
func TestD154EvidenceNamesTheCommand(t *testing.T) {
	for name, src := range map[string]string{
		"gem push":   "system('gem push pkg/wormy-1.0.0.gem')",
		"cargo":      "cp.execSync('cargo publish')",
		"nuget push": "cp.execSync('dotnet nuget push wormy.nupkg')",
		"twine":      "os.system('twine upload dist/*')",
	} {
		_, ev := scanCaps(src)
		found := false
		for _, e := range ev {
			if len(e) > len("registry-publish:") && e[:len("registry-publish:")] == "registry-publish:" {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: evidence should carry a registry-publish: marker, got %v", name, ev)
		}
	}
}
