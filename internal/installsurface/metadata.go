package installsurface

import (
	"sort"
	"strings"
)

// Metadata surface (VC-013, proposal — see docs/VC-013-metadata-surface.md).
//
// Host-interpreted metadata files ship inside a package but carry no declared
// intent of their own: their meaning is assigned by the CONSUMING environment
// (Explorer, Finder, the shell thumbnail cache), not by the artifact. That makes
// them a trigger surface distinct from the package-lifecycle hooks of VC-002 —
// they fire when the OS shell renders the unpacked directory, not when a package
// manager installs. The same bytes are inert on one host and active on another.
//
// This is the static analyzer half of the proposal: it reads the bytes and
// classifies the FACTS (which directive, which UNC/CLSID target). It never lets
// the shell interpret the file (Decision D-04) — detecting the directive IS the
// finding. Severity is host-relative and belongs to the check layer, not here.
//
// The load-bearing case is desktop.ini: an [.ShellClassInfo] IconResource that
// points at a UNC/remote path coerces Explorer into an outbound SMB fetch on
// folder view, leaking the viewer's NTLM hash — the metadata analog of the D-11
// VC-002d forced-auth signature (network egress + credential reach). Everything
// else in the class is disclosure/provenance and stays informational.

// metaKind categorizes a metadata file by how it is assessed.
type metaKind int

const (
	metaNone       metaKind = iota // not a metadata file
	metaDesktopINI                 // parsed for active [.ShellClassInfo] directives
	metaDisclosure                 // presence-only: a host-parsed cache that leaks
)

// metadataDisclosureNames are host-parsed cache files whose mere presence is a
// disclosure/provenance signal. They are binary and are NOT parsed — depSNORT
// records that they shipped, not their contents.
var metadataDisclosureNames = map[string]string{
	".ds_store":         "Finder directory-state cache; leaks directory listing",
	"thumbs.db":         "shell thumbnail cache; leaks thumbnails (incl. of since-deleted files)",
	"ehthumbs.db":       "shell thumbnail cache; leaks thumbnails",
	"ehthumbs_vista.db": "shell thumbnail cache; leaks thumbnails",
}

// benignSystemIconLibs are well-known system libraries a desktop.ini legitimately
// points IconResource/IconFile at. A bare reference to one of these is a normal
// folder-icon customization, not a bundled executable — excluding them keeps the
// exec classification from firing on the common benign case (D-06 discipline).
var benignSystemIconLibs = map[string]bool{
	"shell32.dll": true, "imageres.dll": true, "ddores.dll": true,
	"mmcndmgr.dll": true, "netshell.dll": true, "setupapi.dll": true,
	"pnidui.dll": true, "wmploc.dll": true, "explorer.exe": true,
	"accessibilitycpl.dll": true, "compstui.dll": true,
}

// IsMetadataFile reports whether relPath is a host-interpreted metadata file
// VC-013 assesses. Adapters use this to decide what to collect during a file
// enumeration; the match is on the basename and case-insensitive.
func IsMetadataFile(relPath string) bool {
	return classifyMetadataName(relPath) != metaNone
}

func classifyMetadataName(relPath string) metaKind {
	base := strings.ToLower(metaBase(relPath))
	if base == "desktop.ini" {
		return metaDesktopINI
	}
	if _, ok := metadataDisclosureNames[base]; ok {
		return metaDisclosure
	}
	return metaNone
}

// AnalyzeMetadataSurface classifies host-interpreted metadata files shipped in a
// package. files maps a package-relative path to file content (raw bytes as a
// string); it may hold non-metadata entries, which are ignored. The returned
// Surface records host-independent facts — VC-013 grades severity against the
// target host(s).
func AnalyzeMetadataSurface(files map[string]string) Surface {
	var s Surface

	// Deterministic order: sort the paths rather than ranging the map.
	names := make([]string, 0, len(files))
	for k := range files {
		names = append(names, k)
	}
	sort.Strings(names)

	for _, relPath := range names {
		switch classifyMetadataName(relPath) {
		case metaDesktopINI:
			s.Hooks = append(s.Hooks, analyzeDesktopINI(relPath, files[relPath]))
		case metaDisclosure:
			note := metadataDisclosureNames[strings.ToLower(metaBase(relPath))]
			s.Hooks = append(s.Hooks, Hook{
				Name:     relPath,
				Command:  "host-parsed metadata cache (not executed by depSNORT)",
				Evidence: []string{"metadata:" + relPath, note},
			})
		}
	}
	return s
}

// analyzeDesktopINI parses one desktop.ini for active [.ShellClassInfo]
// directives. A file with no such directive yields a bare provenance hook (no
// capabilities) — the common leftover-from-a-careless-publish case, which is a
// weak signal, not an alarm.
func analyzeDesktopINI(relPath, content string) Hook {
	h := Hook{
		Name:     relPath,
		Command:  truncateStr(content, 400),
		Evidence: []string{"metadata:" + relPath},
	}

	var section string
	for _, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(strings.TrimRight(raw, "\r"))
		if line == "" || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			continue
		}
		// Only [.ShellClassInfo] carries behaviorally interesting directives; a
		// key anywhere else is provenance at most.
		if section != ".shellclassinfo" {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(line[:eq]))
		val := strings.TrimSpace(line[eq+1:])
		switch key {
		case "iconresource", "iconfile":
			classifyIconTarget(&h, key, iconTarget(key, val))
		case "clsid":
			// Folder-as-shell-namespace redirection / masquerade. Weaker than a
			// forced-auth target; recorded as exec-adjacent, graded low-confidence
			// at the check layer.
			h.Caps = appendUnique(h.Caps, CapExec)
			h.Evidence = appendStr(h.Evidence, "desktop.ini CLSID shell redirection: "+truncateStr(val, 80))
		}
	}

	if len(h.Caps) == 0 {
		h.Evidence = appendStr(h.Evidence, "no active [.ShellClassInfo] directive (provenance: authored/handled on a Windows host)")
	}
	return h
}

// classifyIconTarget records the capability implied by an IconResource/IconFile
// target: a UNC/remote path is a forced-authentication sink; a bundled
// executable is a local exec reference; a system icon library is benign.
func classifyIconTarget(h *Hook, key, target string) {
	switch {
	case isUNCOrRemote(target):
		h.Caps = appendUnique(h.Caps, CapNetwork)
		h.Caps = appendUnique(h.Caps, CapCredentials)
		h.Sinks = dedupeSinks(append(h.Sinks, Sink{
			Name:     "SMB/NTLM (forced authentication)",
			Evidence: "desktop.ini " + key + " points at a remote/UNC path: " + truncateStr(target, 120),
		}))
		h.Artifacts = dedupeArtifacts(append(h.Artifacts, Artifact{Ref: target, Remote: true}))
		h.Evidence = appendStr(h.Evidence, "desktop.ini "+key+" forced-auth target: "+truncateStr(target, 120))
	case isBundledExecutable(target):
		h.Caps = appendUnique(h.Caps, CapExec)
		h.Evidence = appendStr(h.Evidence, "desktop.ini "+key+" references a bundled executable: "+truncateStr(target, 120))
	default:
		// Benign local/system icon (e.g. %SystemRoot%\system32\shell32.dll,3).
	}
}

// iconTarget extracts the path portion of an IconResource/IconFile value.
// IconResource is "path,index"; the trailing ,index (which may be a negative
// resource id) is stripped. IconFile is the path directly.
func iconTarget(key, val string) string {
	v := strings.TrimSpace(strings.Trim(strings.TrimSpace(val), `"`))
	if key == "iconresource" {
		if i := strings.LastIndexByte(v, ','); i >= 0 && isIntLiteral(strings.TrimSpace(v[i+1:])) {
			v = strings.TrimSpace(v[:i])
		}
	}
	return v
}

// isUNCOrRemote reports whether an icon target is a UNC share or a remote URL —
// the shapes that cause Explorer to authenticate outbound on folder view. Local
// extended-length paths (\\?\C:\…) and device paths (\\.\…) are NOT remote.
func isUNCOrRemote(s string) bool {
	v := strings.TrimSpace(strings.Trim(s, `"`))
	if v == "" {
		return false
	}
	if strings.HasPrefix(v, `\\`) {
		rest := v[2:]
		if strings.HasPrefix(rest, `?\`) { // extended-length prefix
			return strings.HasPrefix(strings.ToUpper(rest[2:]), `UNC\`)
		}
		if strings.HasPrefix(rest, `.\`) { // device namespace — local
			return false
		}
		return true // \\server\share
	}
	if strings.HasPrefix(v, "//") {
		return true
	}
	lower := strings.ToLower(v)
	if i := strings.Index(lower, "://"); i > 0 {
		return isScheme(lower[:i]) // http, https, ftp, smb, file, …
	}
	return false
}

// isBundledExecutable reports whether target is a package-relative executable —
// an icon path the folder ships and would load. Absolute, drive-rooted, and
// env-var-rooted paths are system references, not bundled; a bare well-known
// system icon library is benign.
func isBundledExecutable(target string) bool {
	v := strings.ToLower(strings.TrimSpace(target))
	if v == "" {
		return false
	}
	switch extOf(v) {
	case ".exe", ".dll", ".cpl", ".scr", ".bat", ".cmd", ".com":
	default:
		return false
	}
	if strings.HasPrefix(v, "%") { // %SystemRoot%\… env-var-rooted
		return false
	}
	if len(v) >= 2 && v[1] == ':' { // C:\… drive-rooted
		return false
	}
	if strings.HasPrefix(v, `\\`) || strings.HasPrefix(v, "/") { // absolute / UNC
		return false
	}
	if benignSystemIconLibs[metaBase(v)] { // bare shell32.dll etc.
		return false
	}
	return true
}

// ---- small helpers --------------------------------------------------------

// metaBase returns the last path segment, tolerating either separator (the map
// keys are forward-slash identifiers, but a caller may pass an OS path).
func metaBase(p string) string {
	if i := strings.LastIndexAny(p, `/\`); i >= 0 {
		return p[i+1:]
	}
	return p
}

func extOf(p string) string {
	base := metaBase(p)
	if i := strings.LastIndexByte(base, '.'); i >= 0 {
		return base[i:]
	}
	return ""
}

func isScheme(s string) bool {
	if len(s) < 2 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '+', r == '-', r == '.':
		default:
			return false
		}
	}
	return true
}

func isIntLiteral(s string) bool {
	if s == "" {
		return false
	}
	i := 0
	if s[0] == '-' || s[0] == '+' {
		i = 1
	}
	if i == len(s) {
		return false
	}
	for ; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
