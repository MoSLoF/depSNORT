package installsurface

import "testing"

// Regression for the same FP sweep that produced D-130 (.profile): "/etc/"
// was matched as a raw substring, like .bashrc or .git/hooks/ — but unlike
// those, "etc" is also a plausible directory-segment name, so the substring
// fired on any relative path that merely NESTS a directory literally named
// "etc" (require('./etc/templates/config.js'), require('./spec/etc/
// config.js')), with nothing to do with the real absolute Unix system
// directory. containsWord's boundary check (D-130's fix for .profile) does
// not fully close this: "." and "/" both pass its "preceding byte is not an
// identifier" test, so ./etc/ would still match. Fixed instead with
// etcAbsolutePathRe (D-131): a whitelist of characters that can legitimately
// precede a genuinely absolute /etc/ path (quote, backtick, whitespace, and
// shell/JS argument separators) — a "." or "/" immediately before it fails
// closed.
func TestPersistenceEtcAbsolutePathPrecision(t *testing.T) {
	hasPersistence := func(src string) bool {
		_, ev := scanCaps(src)
		for _, m := range ev {
			if IsPersistenceMarker(m) {
				return true
			}
		}
		return false
	}

	// Must NOT be flagged as persistence (the false positives): a relative
	// path that merely nests a directory named "etc" somewhere in it.
	benign := map[string]string{
		"relative from root, own etc dir": `require('./etc/templates/config.js')`,
		"nested under another directory":  `const spec = require('./spec/etc/config.js');`,
		"unrelated identifier prefix":     `myEtcHelper('/vendor/etc/thing')`,
	}
	for name, src := range benign {
		if hasPersistence(src) {
			t.Errorf("%s: must NOT raise a persistence marker: %q", name, src)
		}
	}

	// Must still be flagged: a genuinely absolute /etc/ path, in each
	// realistic shape (a bare quoted argument, a shell command string with
	// a redirect, and a plain OS-detection read — deliberately still flagged,
	// since no other persistence marker in this list distinguishes a read
	// from a write either).
	real := map[string]string{
		"bare quoted write":             `fs.writeFileSync('/etc/cron.d/evil', payload)`,
		"shell append via redirect":     `execSync('echo evil >> /etc/rc.local')`,
		"OS-detection read (by design)": `fs.existsSync('/etc/os-release')`,
	}
	for name, src := range real {
		if !hasPersistence(src) {
			t.Errorf("%s: a real absolute /etc/ reference must raise persistence: %q", name, src)
		}
	}
}
