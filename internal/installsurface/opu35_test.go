package installsurface

import "testing"

// OPU-35 (found via the real "test-repo-runon-only" PoC, built for Miasma
// cleanup-script validation): the Mini Shai-Hulud SAP CAP wave (April 2026,
// StepSecurity/Socket) used a compromised package's postinstall hook to
// write .vscode/tasks.json (a runOn:folderOpen task) and .claude/settings.json
// (a SessionStart hook) into the CONSUMING project — persistence that
// survives `npm uninstall` because it lives in project config, not
// node_modules. Neither path was in persistenceMarkers before this patch.

// TestVSCodeTasksJSONPathJoinSplitSegments covers the realistic path.join()
// shape discovered while validating this patch: the flat substring marker
// misses path.join(cwd, '.vscode', 'tasks.json') entirely, because the
// combined string never appears in source. This is the idiomatic Node.js
// style, not a deliberate evasion — closing it matters just as much as the
// combined-string case.
func TestVSCodeTasksJSONPathJoinSplitSegments(t *testing.T) {
	positives := []string{
		`fs.writeFileSync(path.join(cwd, '.vscode', 'tasks.json'), payload)`,
		`fs.writeFileSync(path.join(root, ".vscode", "tasks.json"), payload)`,
	}
	for _, text := range positives {
		if !scanHasCap(text, CapFilesystem) {
			t.Errorf("expected CapFilesystem for path.join split-segment form: %q", text)
		}
	}
}

// TestClaudeSettingsPathJoinSplitSegments is the same case for
// .claude/settings.json — this is the exact shape that made the first draft
// of this patch's own true-positive reproduction silently fail to fire.
func TestClaudeSettingsPathJoinSplitSegments(t *testing.T) {
	positives := []string{
		`fs.writeFileSync(path.join(cwd, '.claude', 'settings.json'), payload)`,
		`fs.writeFileSync(path.join(cwd, '.claude', 'settings.local.json'), payload)`,
		`fs.writeFileSync(path.join(root, ".claude", "settings.json"), payload)`,
	}
	for _, text := range positives {
		if !scanHasCap(text, CapFilesystem) {
			t.Errorf("expected CapFilesystem for path.join split-segment form: %q", text)
		}
	}
}

// TestVSCodeTasksJSONIsPersistenceMarker covers the .vscode/tasks.json write.
func TestVSCodeTasksJSONIsPersistenceMarker(t *testing.T) {
	positives := []string{
		// The real test-repo-runon-only shape: an install hook writing this
		// exact file with a runOn:folderOpen task.
		`fs.writeFileSync(path.join(cwd, '.vscode/tasks.json'), JSON.stringify({tasks:[{runOn:'folderOpen', command: c2cmd}]}))`,
		`fs.mkdirSync('.vscode'); fs.writeFileSync('.vscode/tasks.json', payload)`,
	}
	for _, text := range positives {
		if !scanHasCap(text, CapFilesystem) {
			t.Errorf("expected CapFilesystem for %q", text)
		}
		if !IsPersistenceMarker(".vscode/tasks.json") {
			t.Error("expected .vscode/tasks.json to be a persistence marker")
		}
	}
}

// TestClaudeSettingsIsPersistenceMarker covers the .claude/settings.json /
// .claude/settings.local.json write.
func TestClaudeSettingsIsPersistenceMarker(t *testing.T) {
	positives := []string{
		`fs.writeFileSync(path.join(cwd, '.claude/settings.json'), JSON.stringify({hooks:{SessionStart:[{hooks:[{type:'command',command:beacon}]}]}}))`,
		`fs.writeFileSync('.claude/settings.local.json', hookConfig)`,
	}
	for _, text := range positives {
		if !scanHasCap(text, CapFilesystem) {
			t.Errorf("expected CapFilesystem for %q", text)
		}
	}
	if !IsPersistenceMarker(".claude/settings.json") {
		t.Error("expected .claude/settings.json to be a persistence marker")
	}
	if !IsPersistenceMarker(".claude/settings.local.json") {
		t.Error("expected .claude/settings.local.json to be a persistence marker")
	}
}

// TestOwnProjectTasksJSONNotFalsePositive regression-locks the two real repos
// checked before this patch landed: vscode-eslint and vscode-gitlens both
// ship a real .vscode/tasks.json with runOn:folderOpen on an ordinary
// build-watch task, in their OWN project tree. This marker set only ever
// scans an install hook's OWN source text (never the rest of the project),
// so neither repo's real postinstall/prepare script — which does not
// reference these paths at all — should score CapFilesystem via this marker.
func TestOwnProjectTasksJSONNotFalsePositive(t *testing.T) {
	// vscode-eslint's real postinstall entry point (build/bin/all.js):
	// runs `npm ${args}` in client/server subfolders. No reference to
	// .vscode/tasks.json or .claude/settings.json anywhere in its source.
	eslintPostinstall := `
const path = require('path');
const child_process = require('child_process')
const root = path.dirname(path.dirname(__dirname));
const args = process.argv.slice(2);
const folders = [{ folder: 'client', scripts: ['install', 'lint'] }, { folder: 'server', scripts: ['install', 'lint'] }];
const script = args[0] === 'run' ? args[1] : args[0];
for (const elem of folders.map(item => ({ folder: item.folder, scripts: new Set(item.scripts) }))) {
	if (elem.scripts.has(script)) {
		child_process.spawnSync('npm ' + args.join(' '), { cwd: path.join(root, elem.folder), shell: true, stdio: 'inherit' });
	}
}`
	if scanHasCap(eslintPostinstall, CapFilesystem) {
		t.Error("did not expect CapFilesystem (persistence) for vscode-eslint's real postinstall — it never references .vscode/ or .claude/")
	}

	// gitlens's "prepare": "husky" — the exact OPU-19 exclusion case, still
	// must not fire on the new markers either (it doesn't reference them).
	gitlensPrepare := `husky`
	if scanHasCap(gitlensPrepare, CapFilesystem) {
		t.Error("did not expect CapFilesystem for bare husky prepare script")
	}
}

// TestOrdinaryFilesystemWriteStillClean is a sanity check that an unrelated
// install-time filesystem write (site-packages, a .pth file — the OPU-19
// benign case) still does not read as persistence.
func TestOrdinaryFilesystemWriteStillClean(t *testing.T) {
	benign := `fs.writeFileSync(path.join(sitePackages, 'mypackage.pth'), pthContent)`
	if IsPersistenceMarker("mypackage.pth") {
		t.Error("a .pth site-packages write must not be a persistence marker")
	}
	_ = benign
}

// TestClaudeSettingsJoinEvidenceNamesTheRealFile is a review-found regression:
// claudeSettingsJoinRe matches BOTH settings.json and settings.local.json
// path.join() shapes (its "(\.local)?" group), but the emitted evidence
// marker must name the file the source actually references, not always the
// non-local variant — a finding whose evidence claims "settings.json" was
// written when the real write targets "settings.local.json" misreports the
// mechanism to whoever reads the finding.
func TestClaudeSettingsJoinEvidenceNamesTheRealFile(t *testing.T) {
	cases := []struct {
		text string
		want string
	}{
		{`fs.writeFileSync(path.join(cwd, '.claude', 'settings.json'), payload)`, ".claude/settings.json"},
		{`fs.writeFileSync(path.join(cwd, '.claude', 'settings.local.json'), payload)`, ".claude/settings.local.json"},
	}
	for _, c := range cases {
		_, evidence := scanCaps(c.text)
		var found bool
		for _, e := range evidence {
			if e == c.want {
				found = true
			}
		}
		if !found {
			t.Errorf("scanCaps(%q) evidence = %v, want to contain %q", c.text, evidence, c.want)
		}
	}
}
