package installsurface

import "testing"

// Regression for the OpenShell live-fire: VC-002g persistence fired on the bare
// substring "startup", mislabeling coverage.py's process_startup() .pth and a
// setuptools "on startup" comment as "boot/login persistence (HIGH)". Only a real
// Windows Startup FOLDER (shell:startup, ...\Programs\Startup) is persistence.
func TestPersistenceStartupPrecision(t *testing.T) {
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
		"coverage .pth process_startup": `import sys; exec('coverage.process_startup(slug="pth")')`,
		"setuptools on-startup comment": `# implicit behavior on startup to give higher precedence`,
		"startup as a word":             `logger.info("service startup complete")`,
		"process_startup identifier":    `from coverage import process_startup as process_startup`,
	}
	for name, src := range benign {
		if hasPersistence(src) {
			t.Errorf("%s: must NOT raise a persistence marker", name)
		}
	}

	// Must still be flagged: a genuine Windows Startup-folder write.
	real := map[string]string{
		"shell:startup":        `os.system('copy evil.exe "shell:startup"')`,
		"common startup":       `dst = r"shell:common startup"`,
		"Programs\\Startup":    `open(r"C:\Users\x\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\run.lnk","w")`,
		"Programs/Startup fwd": `path = "AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/x.lnk"`,
	}
	for name, src := range real {
		if !hasPersistence(src) {
			t.Errorf("%s: a real Startup-folder write must raise persistence", name)
		}
	}
}
