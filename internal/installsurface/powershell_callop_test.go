package installsurface

import "testing"

// TestPowerShellCallOperator covers the OPU-27 follow-up: the PowerShell call
// operator is CapExec, but shell `&&` / background `&` — which the old bare "& "
// substring marker wrongly matched — are not. Uses scanHasCap from opu27_test.go.
func TestPowerShellCallOperator(t *testing.T) {
	// Real PowerShell call-operator invocations -> exec.
	execPositives := []string{
		`& "C:\Users\x\payload.exe"`,     // quoted path (the classic use)
		`& '/tmp/p.sh'`,                  // single-quoted
		`& { Invoke-Something }`,         // scriptblock
		`& $payload`,                     // variable invocation
		`&"no-space.exe"`,                // no-space quoted form
		`&$cmd`,                          // no-space variable form
		`iex $x; & "$env:TEMP\drop.exe"`, // chained after another statement
	}
	for _, cmd := range execPositives {
		if !scanHasCap(cmd, CapExec) {
			t.Errorf("expected CapExec for PowerShell call operator %q", cmd)
		}
	}

	// Shell operators that must NOT be read as the call operator (the fix). The
	// old "& " substring marker matched all of these, giving benign hooks a
	// spurious CapExec.
	execNegatives := []string{
		"npm install -g typescript && npm run build", // smart-buffer/socks: && , not a call op
		"tsc -p . && eslint src",                     // chained builds
		"rm -rf dist & echo done",                    // background & then a bare word
		"a && b && c",                                // multiple &&
		"NODE_ENV=test mocha && nyc report",          // env + &&
		`build && "$RUNNER" test`,                    // && directly before a quote (guards the [^&] anchor)
	}
	for _, cmd := range execNegatives {
		if scanHasCap(cmd, CapExec) {
			_, ev := scanCaps(cmd)
			t.Errorf("shell &&/background & must not raise CapExec for %q; evidence=%v", cmd, ev)
		}
	}

	// The smart-buffer/socks hook specifically: still CapNetwork (Part B), but no
	// longer the incidental CapExec.
	const sb = "npm install -g typescript && npm run build"
	if !scanHasCap(sb, CapNetwork) {
		t.Errorf("%q should still reach the network via the install", sb)
	}
	if scanHasCap(sb, CapExec) {
		t.Errorf("%q should no longer carry an incidental CapExec from &&", sb)
	}
}
