package installsurface

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// AnalyzePythonLoadTime scans a Python package's OWN runtime modules for
// module-level code that executes on `import` and carries an escalating
// capability. This is the import-time surface (VC-002L, Decision D-165):
// malicious code injected into an ordinary module — e.g. the telnyx/_client.py
// compromise, where the payload runs on the first `import telnyx` — is a runtime
// trigger that no install-hook analyzer (setup.py / pyproject / .pth) ever sees.
//
// modules maps a package-relative module path (e.g. "telnyx/_client.py") to its
// source. The caller decides which modules to pass (bounded, the package's own
// import surface); this analyzer decides what, if anything, is worth reporting.
//
// The scan is a deliberate LOWER BOUND, tuned hard against false positives
// because import-time code is overwhelmingly benign (config loading, plugin
// registration, capability probing — D-165 §6):
//
//   - Only import-time-reachable code is considered: module-level statements plus
//     the bodies of top-level functions CALLED at module level (one level deep).
//     A helper function that is never invoked at import contributes nothing, and
//     `if __name__ == "__main__":` and class bodies are excluded (they do not run
//     on import).
//   - A hook is emitted ONLY when the reachable code shows a capability
//     COMBINATION the VC-002 family would act on (decode+exec, credential+network,
//     a download cradle, or a named-credential read) — never on bare code, a lone
//     exec, a lone network reach, an embedded-data decode with no exec sink, or an
//     env read. This is stricter than a raw "any capability" gate (see
//     loadTimeEscalates); the threshold is the parameter the spec's §7 corpus
//     evaluation exists to tune before this ever gates.
//   - The number of modules scanned is bounded; the bound is disclosed via
//     Surface.Truncated so a capped scan degrades coverage, not truth.
//
// Nothing is executed (Decision D-04). This analyzer only produces FACTS; a check
// judges them, and per D-165 that judgment is capped at advisory until §7 is met.
func AnalyzePythonLoadTime(modules map[string]string) Surface {
	var s Surface

	names := make([]string, 0, len(modules))
	for name := range modules {
		names = append(names, name)
	}
	sort.Strings(names) // deterministic scan order (Gate H)

	scanned := 0
	for _, name := range names {
		if scanned >= maxLoadTimeRefs {
			s.Truncated = appendStr(s.Truncated,
				fmt.Sprintf("import-time module scan capped at %d modules", maxLoadTimeRefs))
			break
		}
		scanned++
		if h, ok := analyzeLoadTimeModule(name, modules[name]); ok {
			s.Hooks = append(s.Hooks, h)
		}
	}
	return s
}

// analyzeLoadTimeModule reports the import-time hook for one module, if any.
func analyzeLoadTimeModule(rel, source string) (Hook, bool) {
	reachable := pyImportTimeCode(source)
	if strings.TrimSpace(reachable) == "" {
		return Hook{}, false
	}

	// Same inert-text discipline as setup.py module-level (D-25/D-160): drop
	// comments and the module docstring, then the contents of display-sink
	// strings, then all URLs — so documentation, printed help, and badge links
	// cannot fabricate a capability. stripSetupDocStrings is NOT applied: it is
	// scoped to setup()'s long_description/description keywords, which are a
	// setup.py concept, not a runtime module's.
	cleaned := urlRe.ReplaceAllString(stripPyDisplayStrings(stripPyInert(reachable)), "")

	caps, ev := scanCaps(cleaned)

	// Shell-tool network words (curl/wget/certutil/...) are egress only if the
	// code can actually run a shell command or makes an in-language network call;
	// on their own (a printed instruction that survived stripping) they are inert.
	if containsCap(caps, CapNetwork) && !hasLibraryNetworkMarker(cleaned) && !hasShellExecSink(cleaned) {
		caps, ev = dropCap(caps, CapNetwork, ev,
			"curl ", "wget ", "certutil", "bitsadmin", "finger.exe", "msiexec")
	}

	// IMDS is reached via a URL that the strip above removed before credential
	// scanning; recognize it on the raw reachable source and elevate to a
	// credential read (OPU-19 Part B, mirrored from analyzeSetupPy).
	if m := imdsRe.FindString(reachable); m != "" {
		caps = appendUnique(caps, CapCredentials)
		ev = appendStr(ev, "imds:"+m)
	}

	if !loadTimeEscalates(caps) {
		return Hook{}, false
	}

	h := Hook{
		Name:     "module-load:" + rel,
		Command:  "module executes at import (no lifecycle hook required): " + rel,
		Caps:     caps,
		Evidence: appendStr(ev, "import-time-execution"),
		Sinks:    findSinks(cleaned),
	}
	// URL artifacts only from lines that also make a network call (mirrors
	// analyzeSetupPy): a bare URL string is metadata, a fetched one is a target.
	for _, line := range strings.Split(reachable, "\n") {
		if hasNetworkCall(line) {
			for _, u := range urlRe.FindAllString(line, -1) {
				h.Artifacts = append(h.Artifacts, Artifact{Ref: u, Remote: true})
			}
		}
	}
	h.Artifacts = dedupeArtifacts(h.Artifacts)
	h.Sinks = dedupeSinks(h.Sinks)
	return h, true
}

// loadTimeEscalates reports whether a capability set is worth an import-time hook.
// It requires a COMBINATION the VC-002 family acts on, not the raw presence of any
// capability, because import-time code legitimately execs (capability probes),
// reaches the network (telemetry, config), and decodes data (fonts, certs). Only
// the combinations below distinguish a loader/exfil from that benign background:
//
//   - obfuscation + exec  -> decode-and-execute loader (VC-002e shape; telnyx/litellm)
//   - credentials + network -> credential exfil (VC-002d shape)
//   - cradle               -> fetch-and-run in one step (VC-002f shape)
//   - credentials          -> a NAMED secret read at import (id_rsa, NPM_TOKEN, ...),
//     which has no benign reason to run on `import`
//
// A lone exec, a lone network reach, or an embedded-data decode with no exec sink
// is NOT enough. This is deliberately tighter than the spec's §5 list; the bare
// signals are deferred to the §7 corpus evaluation before any promotion.
func loadTimeEscalates(caps []Capability) bool {
	has := func(c Capability) bool { return containsCap(caps, c) }
	switch {
	case has(CapObfuscation) && has(CapExec):
		return true
	case has(CapCredentials) && has(CapNetwork):
		return true
	case has(CapCradle):
		return true
	case has(CapCredentials):
		return true
	default:
		return false
	}
}

var (
	pyDefRe       = regexp.MustCompile(`^(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(`)
	pyClassRe     = regexp.MustCompile(`^class\s+[A-Za-z_]\w*`)
	pyMainGuardRe = regexp.MustCompile(`^if\s+__name__\s*==`)
)

// pyImportTimeCode returns the subset of a module's source that runs on `import`:
// module-level statements, plus the bodies of top-level functions that are called
// at module level. Class bodies and `if __name__ == "__main__":` guards are
// excluded — neither runs on import. Function-call resolution is one level deep (a
// lower bound: a payload reached only through a call inside a called function is
// not followed), and called-function bodies are appended in sorted order so the
// scanned text — and therefore the resulting evidence — is deterministic.
func pyImportTimeCode(src string) string {
	blocks := pyTopLevelBlocks(src)
	defs := map[string]string{}
	var moduleLevel []string
	for _, blk := range blocks {
		first := blk
		if i := strings.IndexByte(blk, '\n'); i >= 0 {
			first = blk[:i]
		}
		first = strings.TrimSpace(first)
		switch {
		case pyDefRe.MatchString(first):
			defs[pyDefRe.FindStringSubmatch(first)[1]] = blk
		case pyClassRe.MatchString(first):
			// class body does not run at import unless instantiated at module
			// level; the prototype lower bound skips it.
		case pyMainGuardRe.MatchString(first):
			// script-only code, not import-time.
		default:
			moduleLevel = append(moduleLevel, blk)
		}
	}

	moduleText := strings.Join(moduleLevel, "\n")

	var called []string
	for name := range defs {
		if regexp.MustCompile(`\b` + regexp.QuoteMeta(name) + `\s*\(`).MatchString(moduleText) {
			called = append(called, name)
		}
	}
	sort.Strings(called)

	var b strings.Builder
	b.WriteString(moduleText)
	for _, name := range called {
		b.WriteString("\n")
		b.WriteString(defs[name])
	}
	return b.String()
}

// pyTopLevelBlocks splits source into top-level blocks: each block is an
// indent-0 line together with the indented lines that follow it. Blank lines
// attach to the current block. This lets the caller classify each block by its
// first line (def / class / statement) without a full parser.
func pyTopLevelBlocks(src string) []string {
	lines := strings.Split(src, "\n")
	var blocks []string
	var cur []string
	flush := func() {
		if len(cur) > 0 {
			blocks = append(blocks, strings.Join(cur, "\n"))
			cur = nil
		}
	}
	for _, ln := range lines {
		if ln == "" {
			if len(cur) > 0 {
				cur = append(cur, ln)
			}
			continue
		}
		if ln[0] == ' ' || ln[0] == '\t' {
			cur = append(cur, ln)
			continue
		}
		flush()
		cur = []string{ln}
	}
	flush()
	return blocks
}
