package installsurface

import "testing"

// Regression for an FP sweep of persistenceMarkers (D-130, following D-129):
// ".profile" is punctuation-anchored, so it was matched as a raw substring
// like .bashrc or .git/hooks/ — but unlike those, "profile" is also a common
// object-property/identifier SUFFIX, so `user.profileImage`,
// `settings.profileData`, and bare `options.profile` all contain the literal
// substring ".profile" with nothing to do with the shell dotfile technique.
// Routed through containsWord — the same dual-boundary check identifier-shaped
// markers (systemd, crontab) already use — since the real technique always
// writes/references ".profile" as a complete path component (quote, path
// separator, or whitespace on both sides), never continued by or continuing
// from another identifier character.
func TestPersistenceDotProfilePrecision(t *testing.T) {
	hasPersistence := func(src string) bool {
		_, ev := scanCaps(src)
		for _, m := range ev {
			if IsPersistenceMarker(m) {
				return true
			}
		}
		return false
	}

	// Must NOT be flagged as persistence (the false positives).
	benign := map[string]string{
		"property access, extended suffix": `const data = user.profileImage;`,
		"property access, another suffix":  `export function f() { return settings.profileData; }`,
		"property access, Id suffix":       `analytics.profileId = getId();`,
		"bare property access, no suffix":  `if (window.chrome && window.chrome.profile) {}`,
		"options.profile pattern":          `this.profile = options.profile || 'default';`,
		"unrelated backup filename":        `path.join(x, 'my.profile.bak')`,
	}
	for name, src := range benign {
		if hasPersistence(src) {
			t.Errorf("%s: must NOT raise a persistence marker: %q", name, src)
		}
	}

	// Must still be flagged: a genuine shell-profile write, in each realistic
	// shape (path.join, string concatenation, and a shell command string).
	real := map[string]string{
		"path.join with os.homedir()": `fs.appendFileSync(path.join(os.homedir(), '.profile'), payload)`,
		"string concatenation":        `fs.appendFileSync(home + '/.profile', payload)`,
		"shell append via execSync":   `execSync('echo evil >> ~/.profile')`,
		"bare quoted filename":        `fs.writeFileSync('.profile', data)`,
	}
	for name, src := range real {
		if !hasPersistence(src) {
			t.Errorf("%s: a real .profile write must raise persistence: %q", name, src)
		}
	}
}
