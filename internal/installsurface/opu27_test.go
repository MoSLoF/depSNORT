package installsurface

import "testing"

// hasCap reports whether scanCaps assigned capability c to text.
func scanHasCap(text string, c Capability) bool {
	caps, _ := scanCaps(text)
	for _, x := range caps {
		if x == c {
			return true
		}
	}
	return false
}

// TestPkgRunnerNetworkExec covers OPU-27 Part A: package runners that
// fetch-and-execute a registry package (npx / dlx / bunx) must be Network+Exec.
func TestPkgRunnerNetworkExec(t *testing.T) {
	positives := []string{
		"npx some-random-cli",         // a non-allowlisted target (cf. only-allow, Part D)
		"npx --yes some-cli build",    // flags before the package name
		"pnpm dlx some-generator",     // pnpm remote exec
		"yarn dlx @scope/tool",        // yarn remote exec, scoped
		"bunx create-thing",           // bun runner
		"postinstall && npx evildoer", // chained after another command
	}
	for _, cmd := range positives {
		if !scanHasCap(cmd, CapNetwork) {
			t.Errorf("expected CapNetwork for %q", cmd)
		}
		if !scanHasCap(cmd, CapExec) {
			t.Errorf("expected CapExec for %q", cmd)
		}
	}

	// Explicitly offline runners do not reach the network.
	offline := []string{
		"npx --no-install local-bin",
		"npx --offline some-cli",
	}
	for _, cmd := range offline {
		if scanHasCap(cmd, CapNetwork) {
			t.Errorf("did not expect CapNetwork for offline runner %q", cmd)
		}
	}

	// `pnpm exec` / `yarn exec` run an already-installed local bin — no fetch.
	for _, cmd := range []string{"pnpm exec tsc", "yarn exec eslint"} {
		if scanHasCap(cmd, CapNetwork) {
			t.Errorf("did not expect CapNetwork for local exec %q", cmd)
		}
	}
}

// scanEvidence returns the evidence markers scanCaps recorded for text.
func scanEvidence(text string) []string {
	_, ev := scanCaps(text)
	return ev
}

// hasEvidence reports whether scanCaps recorded a marker equal to want for text.
func hasEvidence(text, want string) bool {
	for _, m := range scanEvidence(text) {
		if m == want {
			return true
		}
	}
	return false
}

// TestBenignRunnerAllowlist covers OPU-27 Part D: a runner whose target is a
// known-benign guard clause (only-allow) is disclosed but not scored, yet a benign
// or offline runner cannot launder a hostile one in the same hook, and a typosquat
// of an allowlisted name still scores (exact-match discipline).
func TestBenignRunnerAllowlist(t *testing.T) {
	// The meshclaw case: `npx only-allow pnpm` is a package-manager guard — quiet
	// on both capability axes, but disclosed via a benign-runner evidence marker.
	const guard = "npx only-allow pnpm"
	if scanHasCap(guard, CapNetwork) || scanHasCap(guard, CapExec) {
		t.Errorf("%q (a known guard clause) must not raise network/exec", guard)
	}
	if !hasEvidence(guard, "benign-runner:only-allow") {
		t.Errorf("%q should be disclosed as benign-runner:only-allow; evidence=%v", guard, scanEvidence(guard))
	}
	// only-allow@2 (versioned) is the same target — still benign.
	if scanHasCap("npx only-allow@2 pnpm", CapNetwork) {
		t.Errorf("versioned only-allow@2 should still be benign")
	}

	// A benign prefix must NOT launder a hostile runner in the same hook.
	const laundered = "npx only-allow pnpm && npx evildoer"
	if !scanHasCap(laundered, CapNetwork) || !scanHasCap(laundered, CapExec) {
		t.Errorf("%q: the second runner (evildoer) must still score network+exec", laundered)
	}
	if !hasEvidence(laundered, "pkg-runner:evildoer") {
		t.Errorf("%q should name the hostile target evildoer; evidence=%v", laundered, scanEvidence(laundered))
	}

	// An OFFLINE prefix must not launder a hostile runner either (per-invocation).
	const offlineLaundered = "npx --offline safe && npx evildoer"
	if !scanHasCap(offlineLaundered, CapNetwork) {
		t.Errorf("%q: the second, online runner must still reach the network", offlineLaundered)
	}

	// Exact-match discipline: a typosquat of only-allow is NOT benign.
	for _, squat := range []string{"npx only-alow pnpm", "npx only-allow-evil pnpm"} {
		if !scanHasCap(squat, CapNetwork) || !scanHasCap(squat, CapExec) {
			t.Errorf("typosquat %q must score network+exec (distance-0 allowlist)", squat)
		}
	}
}

// TestPkgInstallNetwork covers OPU-27 Part B: a hook invoking a package manager
// to install from a registry reaches the network (smart-buffer/socks shape).
func TestPkgInstallNetwork(t *testing.T) {
	positives := []string{
		"npm install -g typescript && npm run build", // the socks/smart-buffer hook
		"npm i left-pad",
		"npm ci",
		"pnpm add lodash",
		"yarn add react",
		"pip install requests",
		"pip3 install --user evil",
		"python -m pip install thing",
		"gem install bundler",
		"cargo install ripgrep",
		"go install example.com/x@latest",
	}
	for _, cmd := range positives {
		if !scanHasCap(cmd, CapNetwork) {
			t.Errorf("expected CapNetwork for %q", cmd)
		}
	}

	// `npm run <script>` does NOT fetch — must stay quiet on the network axis.
	benign := []string{
		"npm run build",
		"npm run test",
		"tsc -p tsconfig-build.json",
		"node-gyp-build", // @serialport/bindings-cpp: native build, not a fetch
	}
	for _, cmd := range benign {
		if scanHasCap(cmd, CapNetwork) {
			t.Errorf("did not expect CapNetwork for benign build %q", cmd)
		}
	}
}

// TestGitHookPersistence covers OPU-27 Part C: explicit git-hook-path
// manipulation is persistence; bare husky is deliberately NOT.
func TestGitHookPersistence(t *testing.T) {
	persistence := []string{
		"git config core.hooksPath hooks || true", // the ip-address prepare hook
		"cp payload .git/hooks/pre-commit",
	}
	for _, cmd := range persistence {
		if !scanHasCap(cmd, CapFilesystem) {
			t.Errorf("expected CapFilesystem for %q", cmd)
		}
		caps, ev := scanCaps(cmd)
		_ = caps
		var isPersist bool
		for _, m := range ev {
			if IsPersistenceMarker(m) {
				isPersist = true
			}
		}
		if !isPersist {
			t.Errorf("expected a persistence marker for %q; evidence=%v", cmd, ev)
		}
	}

	// Bare husky must NOT be flagged as persistence (warning-tax discipline).
	for _, cmd := range []string{"husky", "husky install"} {
		_, ev := scanCaps(cmd)
		for _, m := range ev {
			if IsPersistenceMarker(m) {
				t.Errorf("husky should not be a persistence marker; got %q for %q", m, cmd)
			}
		}
	}
}
