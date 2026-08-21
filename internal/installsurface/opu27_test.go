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
		"npx only-allow pnpm",         // the meshclaw meshtastic hooks
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
