package installsurface

import (
	"strings"
	"testing"
)

// hasFilesystemPersistence reports whether scanCaps flags text with a
// CapFilesystem whose evidence marker is a persistence marker.
func hasFilesystemPersistence(text string) bool {
	_, ev := scanCaps(text)
	for _, m := range ev {
		if IsPersistenceMarker(m) {
			return true
		}
	}
	return false
}

// Regression for the beats live-fire: the persistence marker "systemd" matched
// the substring inside the mkwinsyscall "-systemdll" flag, firing VC-002g HIGH.
// Identifier-shaped persistence markers must match on word boundaries, while
// genuine references (and macOS auto-run dirs) must still be caught.
func TestPersistenceWordBoundary(t *testing.T) {
	// Must NOT fire — the marker is inside a larger identifier.
	for _, s := range []string{
		"go:generate mkwinsyscall.exe -systemdll -output zsyscall_windows.go",
		"import crontabber", // crontab inside crontabber
		"var systemdConfigParser = 1",
	} {
		if hasFilesystemPersistence(s) {
			t.Errorf("must NOT flag persistence (substring inside identifier): %q", s)
		}
	}

	// Must STILL fire — a genuine persistence reference.
	for _, s := range []string{
		"cp unit.service /etc/systemd/system/",
		"systemctl enable evil.service",
		"crontab -e",
		"cp launchagent.plist ~/Library/LaunchAgents/",
		"cp d.plist ~/Library/LaunchDaemons/",
		"echo x >> ~/.bashrc",
	} {
		if !hasFilesystemPersistence(s) {
			t.Errorf("must flag persistence (genuine reference): %q", s)
		}
	}
}

func TestContainsWord(t *testing.T) {
	cases := []struct {
		hay, word string
		want      bool
	}{
		{"-systemdll", "systemd", false},
		{"/etc/systemd/system", "systemd", true},
		{"a systemd b", "systemd", true},
		{"systemd", "systemd", true},
		{"presystemd", "systemd", false},
		{"launchdaemons", "launchd", false}, // why LaunchDaemons is now explicit
	}
	for _, c := range cases {
		if got := containsWord(strings.ToLower(c.hay), c.word); got != c.want {
			t.Errorf("containsWord(%q,%q)=%v want %v", c.hay, c.word, got, c.want)
		}
	}
}
