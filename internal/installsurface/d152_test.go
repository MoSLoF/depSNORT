package installsurface

import (
	"strings"
	"testing"
)

// D-152: the propagation phase of the Shai-Hulud worm family. depSNORT detected
// the credential phase (VC-002c/d) and the persistence phase (VC-002g), and its
// graph vocabulary named the propagation phase — graph.EdgeRepublish, "worm loop
// back into the declared tree" — but nothing ever produced it. A hook running
// `npm publish` scanned as plain [exec], indistinguishable from a hook that
// shells out to a compiler. IOCs in fixtures are inert.

func d152Caps(t *testing.T, src string) []Capability {
	t.Helper()
	caps, _ := scanCaps(src)
	return caps
}

// TestD152RegistryPublishIsPropagation: the worm step itself, in the forms it
// actually takes.
func TestD152RegistryPublishIsPropagation(t *testing.T) {
	for name, src := range map[string]string{
		"npm cli":      "require('child_process').execSync('npm publish --access public');",
		"pnpm cli":     "cp.execSync('pnpm publish --no-git-checks');",
		"yarn cli":     "cp.exec('yarn publish --new-version patch');",
		"bun cli":      "cp.execSync('bun publish');",
		"version bump": "cp.execSync('npm version patch');",
		"programmatic": "const {publish}=require('libnpmpublish'); await publish(mani, tar, opts);",
		"registry-api": "const f=require('npm-registry-fetch'); await f.json('/-/package/x/dist-tags',{method:'PUT'});",
	} {
		if !hasCap(d152Caps(t, src), CapPropagate) {
			t.Errorf("%s: expected CapPropagate, got %v", name, d152Caps(t, src))
		}
	}
}

// TestD152DryRunIsNotPropagation is the false-positive boundary that matters
// most: `npm publish --dry-run` is how a legitimate release script or CI job
// REHEARSES a publish. Flagging it would fire on exactly the careful tooling
// that has published nothing.
func TestD152DryRunIsNotPropagation(t *testing.T) {
	for _, src := range []string{
		"cp.execSync('npm publish --dry-run');",
		"cp.execSync('npm publish --access public --dry-run');",
		"cp.execSync('pnpm publish --dry-run')",
	} {
		if hasCap(d152Caps(t, src), CapPropagate) {
			t.Errorf("a --dry-run rehearsal is not propagation: %q -> %v", src, d152Caps(t, src))
		}
	}
}

// TestD152LifecycleHookNamesAreNotPropagation: "prepublish"/"postpublish" are
// hook NAMES present in a large share of package.json files. Matching the word
// "publish" alone would flag them all — the false-positive flood the verb+
// package-manager anchoring exists to avoid.
func TestD152LifecycleHookNamesAreNotPropagation(t *testing.T) {
	for _, src := range []string{
		`{"scripts":{"prepublish":"tsc","postpublish":"echo done"}}`,
		"npm run prepublishOnly",
		"// see the prepublish hook for details",
	} {
		if hasCap(d152Caps(t, src), CapPropagate) {
			t.Errorf("a lifecycle hook NAME is not a publish: %q -> %v", src, d152Caps(t, src))
		}
	}
}

// TestD152UnrelatedPublishVerbsAreNotPropagation: pub/sub, event emitters and
// message queues all use publish(). Only a registry publish counts.
func TestD152UnrelatedPublishVerbsAreNotPropagation(t *testing.T) {
	for _, src := range []string{
		"emitter.publish('event', payload);",
		"await redis.publish(channel, msg);",
		"this.publish({topic: 'x'});",
		"mqttClient.publish('sensors/temp', '21');",
	} {
		if hasCap(d152Caps(t, src), CapPropagate) {
			t.Errorf("a non-registry publish() is not propagation: %q -> %v", src, d152Caps(t, src))
		}
	}
}

// TestD152OrdinaryInstallHookIsUnaffected is the broad benign baseline: the
// commands real install hooks actually run.
//
// It also carries the anti-vacuity assertion for every negative test in this
// file. "no CapPropagate" is the expected result of a scanner that is working
// AND of a scanner that has stopped returning anything at all, so a suite of
// pure negatives can go green on a dead scanCaps. Proving the scanner still
// classifies these inputs — `npm install` is a manager install, so it must
// still surface caps — makes the absence of CapPropagate mean something.
func TestD152OrdinaryInstallHookIsUnaffected(t *testing.T) {
	for _, src := range []string{
		"node-gyp rebuild",
		"npm install && npm run build",
		"tsc -p tsconfig.json",
		"npm run test -- --coverage",
	} {
		if hasCap(d152Caps(t, src), CapPropagate) {
			t.Errorf("an ordinary install hook must not be propagation: %q -> %v", src, d152Caps(t, src))
		}
	}
	if live := "cp.execSync('npm install --ignore-scripts')"; len(d152Caps(t, live)) == 0 {
		t.Fatalf("scanCaps classified nothing for %q — every negative case in this file is vacuous", live)
	}
}

// TestD152PropagationEvidenceNamesTheCommand: the finding has to say WHAT it
// saw, not merely that it saw something (the D-142/D-144 lineage).
func TestD152PropagationEvidenceNamesTheCommand(t *testing.T) {
	_, ev := scanCaps("cp.execSync('npm publish --access public');")
	joined := strings.Join(ev, ",")
	if !strings.Contains(joined, "registry-publish:") || !strings.Contains(joined, "npm publish") {
		t.Errorf("evidence should name the publish command, got %v", ev)
	}
}
