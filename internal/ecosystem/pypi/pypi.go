// Package pypi is the second ecosystem adapter. It exists to prove the
// ecosystem seam is real rather than decorative: the graph model, check
// contract, verdict engine, and every emitter are reused unchanged, and only
// parsing and name normalization differ.
//
// Supported inputs, both stdlib-parseable:
//
//   - requirements.txt — fully pinned (`name==version`). pip-compile output also
//     carries `# via <parent>` comments, which are the only place a
//     requirements file records WHICH package pulled in which; those are parsed
//     back into depends-on edges.
//   - Pipfile.lock — JSON, with `default` and `develop` sections.
//
// Poetry's poetry.lock and uv.lock are TOML. Go has no TOML parser in its
// standard library, and adding one would put a third-party dependency into a
// supply-chain-safety tool (Decision D-10). Those formats therefore wait for a
// minimal in-tree TOML subset reader rather than being bought with a dependency.
//
// Nothing here installs or executes anything (Decision D-04): pip is never run.
package pypi

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"ihbv.io/depsnort/internal/datasource"
	"ihbv.io/depsnort/internal/graph"
	"ihbv.io/depsnort/internal/pep508"
	"ihbv.io/depsnort/internal/purl"
	"ihbv.io/depsnort/internal/securefs"
)

// Adapter implements ecosystem.Adapter for PyPI.
type Adapter struct {
	// Sdist fetches source distributions for install-surface analysis.
	// Nil means install-surface extraction is skipped (offline, or not configured).
	Sdist *SdistFetcher
	// ScanRoot is the top-level path depsnort was pointed at. It bounds where a
	// requirements.txt `-r`/`-c` include may be followed (D-54): an include is
	// read only if it resolves to a regular file inside this root, so a hostile
	// checkout cannot make the scanner read `-r ../../etc/passwd`. Empty means the
	// including file's own directory is used as the bound.
	ScanRoot string
}

// New returns a PyPI adapter without sdist fetching.
func New() *Adapter { return &Adapter{} }

// NewWithSdist returns a PyPI adapter with sdist fetching enabled for
// install-surface analysis.
//
// offline is passed THROUGH to the fetcher rather than used to drop it. The
// fetcher already refuses the network when offline and serves from its cache,
// so keeping it has two effects an offline scan wants: an sdist already cached
// is still analyzed, and one that is not becomes a DISCLOSED gap ("not in
// cache (offline)") instead of a silent skip.
//
// Dropping it did the opposite (D-141): every PyPI dependency's install
// surface went unexamined and the run still reported "0 partial
// install-surface extraction(s)" — a skip rendered as an absence, which is
// the R-01 invisibility this codebase exists to refuse. -offline is a mode
// people run precisely where honest coverage matters most.
func NewWithSdist(cache *datasource.Cache, offline bool) *Adapter {
	return &Adapter{Sdist: NewSdistFetcher(cache, offline)}
}

// Name implements ecosystem.Adapter.
func (*Adapter) Name() string { return "pypi" }

const (
	requirementsName = "requirements.txt"
	pipfileLockName  = "Pipfile.lock"
	pyprojectName    = "pyproject.toml"
	setupPyName      = "setup.py"
)

// inputPath resolves a directory or file to a supported lockfile path and its
// kind, or ("", "").
func inputPath(path string) (file, kind string) {
	info, err := os.Stat(path)
	if err != nil {
		return "", ""
	}
	if info.IsDir() {
		// uv.lock is a fully-resolved lockfile that expresses inter-package
		// edges — the richest PyPI input there is. Prefer it over everything
		// below (a manifest, a flat lockfile, or a requirements list).
		if p := filepath.Join(path, uvLockName); fileExists(p) {
			return p, "uv"
		}
		// poetry.lock is likewise a fully-resolved TOML lockfile with edges;
		// prefer it over the flat Pipfile.lock and the pyproject manifest.
		if p := filepath.Join(path, poetryLockName); fileExists(p) {
			return p, "poetry"
		}
		if p := filepath.Join(path, pdmLockName); fileExists(p) {
			return p, "pdm"
		}
		// pylock.toml is the PEP 751 standard, tool-agnostic resolved lockfile;
		// it carries edges when the locker records them, so it ranks with the
		// other fully-resolved TOML lockfiles, above the flat Pipfile.lock.
		if p := filepath.Join(path, pylockName); fileExists(p) {
			return p, "pylock"
		}
		// Pipfile.lock is a true lockfile; prefer it over requirements.txt.
		if p := filepath.Join(path, pipfileLockName); fileExists(p) {
			return p, "pipfile"
		}
		if p := filepath.Join(path, requirementsName); fileExists(p) {
			return p, "requirements"
		}
		// A non-canonical requirements file (requirements-dev.txt,
		// test-requirements.txt, requirements/*.txt handled downstream) with no
		// canonical requirements.txt still marks a Python project — split
		// requirements is a dominant convention, and dev/test/CI deps are a real
		// install-time surface (OPU-13). The first such file (sorted) anchors the
		// project; parseRequirements reads the rest as siblings.
		if p := firstRequirementsSibling(path); p != "" {
			return p, "requirements"
		}
		// pyproject.toml is the lowest-priority PyPI input: it is a manifest, not
		// a lockfile, so its deps are declared (name + constraint) and expansion
		// presumes their versions. Only treated as a project root when it
		// actually declares dependencies (checked in parsePyproject).
		// Pipfile is pipenv's MANIFEST; reached only when there is no Pipfile.lock
		// (checked above) and only when it declares deps, mirroring pyproject.
		if p := filepath.Join(path, pipfileName); fileExists(p) && pipfileDeclaresDeps(p) {
			return p, "pipfile-manifest"
		}
		if p := filepath.Join(path, pyprojectName); fileExists(p) && pyprojectDeclaresDeps(p) {
			return p, "pyproject"
		}
		// setup.py is the last resort: statically parseable only for the common
		// literal/variable forms (D-04 forbids running it), gated so a setup.py
		// whose deps are computed dynamically is not claimed as a project.
		if p := filepath.Join(path, setupPyName); fileExists(p) && setuppyDeclaresDeps(p) {
			return p, "setuppy"
		}
		return "", ""
	}
	switch base := filepath.Base(path); {
	case base == uvLockName:
		return path, "uv"
	case base == poetryLockName:
		return path, "poetry"
	case base == pdmLockName:
		return path, "pdm"
	case isPylockFile(base):
		return path, "pylock"
	case base == pipfileLockName:
		return path, "pipfile"
	case base == pipfileName:
		if pipfileDeclaresDeps(path) {
			return path, "pipfile-manifest"
		}
	case base == pyprojectName:
		if pyprojectDeclaresDeps(path) {
			return path, "pyproject"
		}
	case base == setupPyName:
		if setuppyDeclaresDeps(path) {
			return path, "setuppy"
		}
	case isRequirementsFile(base):
		// requirements.txt AND its non-canonical siblings (requirements-dev.txt,
		// test-requirements.txt, …) are recognized when pointed at directly, so a
		// dev/test requirements file is no longer "nothing to scan" (OPU-13).
		return path, "requirements"
	}
	return "", ""
}

func fileExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && !info.IsDir()
}

// isPylockFile reports whether a filename is a PEP 751 lock file: the canonical
// "pylock.toml" or a named variant matching r"^pylock\.([^.]+)\.toml$".
func isPylockFile(name string) bool {
	if name == pylockName {
		return true
	}
	if !strings.HasPrefix(name, "pylock.") || !strings.HasSuffix(name, ".toml") {
		return false
	}
	mid := strings.TrimSuffix(strings.TrimPrefix(name, "pylock."), ".toml")
	return mid != "" && !strings.Contains(mid, ".")
}

// isRequirementsFile reports whether a filename is a pip requirements file by
// the split-requirements convention: a .txt whose name contains "requirements"
// (requirements.txt, requirements-dev.txt, test-requirements.txt,
// dev-requirements.txt, requirements_test.txt, …). A constraints.txt does not
// match — it constrains versions, it does not declare installed packages.
func isRequirementsFile(name string) bool {
	l := strings.ToLower(name)
	return strings.HasSuffix(l, ".txt") && strings.Contains(l, "requirements")
}

// firstRequirementsSibling returns the alphabetically first requirements file in
// dir, or "" if none — the anchor for a Python project that ships split
// requirements without a canonical requirements.txt.
func firstRequirementsSibling(dir string) string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && isRequirementsFile(e.Name()) {
			names = append(names, e.Name())
		}
	}
	if len(names) == 0 {
		return ""
	}
	sort.Strings(names)
	return filepath.Join(dir, names[0])
}

// Detect implements ecosystem.Adapter.
func (*Adapter) Detect(path string) bool {
	f, _ := inputPath(path)
	return f != ""
}

// Resolve implements ecosystem.Adapter.
func (a *Adapter) Resolve(path string) (*graph.Graph, error) {
	file, kind := inputPath(path)
	if file == "" {
		return nil, fmt.Errorf("pypi: no %s or %s found at %q", requirementsName, pipfileLockName, path)
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("pypi: reading %s: %w", file, err)
	}
	switch kind {
	case "uv":
		return parseUvLock(path, raw)
	case "poetry":
		return parsePoetryLock(path, raw)
	case "pdm":
		return parsePdmLock(path, raw)
	case "pylock":
		return parsePylock(path, raw)
	case "pipfile":
		return parsePipfileLock(path, raw)
	case "pipfile-manifest":
		return parsePipfile(path, raw)
	case "pyproject":
		return parsePyproject(path, raw)
	case "setuppy":
		return parseSetupPy(path, raw)
	default:
		return parseRequirements(path, raw, file, a.containmentRoot(path, file))
	}
}

// containmentRoot returns the directory that bounds `-r`/`-c` include following
// for a requirements file. It is the top-level scan root when one was set (so a
// monorepo's shared `../requirements/base.txt` is reachable), otherwise the
// requirements file's own directory. Either way securefs enforces that an
// include escaping it — via `..`, an absolute path, or a symlink — is refused
// and disclosed rather than read (D-54).
func (a *Adapter) containmentRoot(path, file string) string {
	root := a.ScanRoot
	if root == "" {
		root = path
	}
	if info, err := os.Stat(root); err != nil || !info.IsDir() {
		root = filepath.Dir(file)
	}
	return root
}

// rootNode creates the synthetic project root for a Python project, named after
// the containing directory (requirements files carry no project name).
func rootNode(g *graph.Graph, path string) *graph.Node {
	name := filepath.Base(strings.TrimSuffix(filepath.Clean(path), string(filepath.Separator)))
	if name == "." || name == "" || name == requirementsName || name == pipfileLockName {
		name = "python-project"
	}
	if strings.HasSuffix(name, ".txt") || strings.HasSuffix(name, ".lock") || name == pyprojectName || name == setupPyName {
		name = filepath.Base(filepath.Dir(path))
	}
	id := purl.NewPyPI(name, "0.0.0").String()
	n := g.AddNode(&graph.Node{
		ID: id, Ecosystem: "pypi", Name: purl.NormalizePyPI(name), Version: "0.0.0", Depth: 0,
		// "0.0.0" is always a placeholder here — nothing in this adapter reads a
		// real version out of setup.py/pyproject.toml (consistent with the
		// zero-execution ethos: a setuptools_scm/hatch-vcs project computes its
		// real version by running git, which this tool will never do). Tagged
		// so a reader can tell "genuinely 0.0.0" apart from "could not
		// determine" without already knowing the project.
		Attr: map[string]string{"pypi.version_source": "unresolved-placeholder"},
	})
	g.MarkRoot(id)
	return n
}

// ---- requirements.txt ----------------------------------------------------

// unparseableToken renders an unreadable requirements.txt line as one
// disclosure token for graph.AttrUnresolved.
//
// Two constraints on the shape, both load-bearing: AttrUnresolved is
// comma-joined at the root and re-split by internal/graph/coverage.go with no
// escaping, so the token must be comma-free; and the line scanner permits a
// 4 MB line, so it must be length-bounded before it reaches a graph attribute.
// Truncation is rune-aware so a multi-byte character is never cut in half.
func unparseableToken(line string) string {
	const max = 60
	t := strings.TrimSpace(line)
	t = strings.ReplaceAll(t, ",", " ")
	if r := []rune(t); len(r) > max {
		t = string(r[:max]) + "…"
	}
	return "<unparseable: " + t + ">"
}

// maxIncludeDepth bounds how deep a chain of `-r`/`-c` includes is followed. A
// requirements file may pull in another (base.txt -> prod.txt -> ...); the bound
// stops a maliciously deep or accidentally cyclic chain, and any include past it
// is disclosed as an unfollowed gap rather than silently dropped.
const maxIncludeDepth = 32

// reqEntry is one pinned requirement, with its pip-compile `via` parents.
type reqEntry struct {
	name    string
	version string
	vias    []string
	marker  string
}

// reqAccum gathers what a requirements file — and every file it includes —
// declares, so a `-r`/`-c` chain resolves into one project rather than the top
// file's visible lines alone (D-54). Following the includes is the whole point:
// a requirements.txt that is a few visible pins plus `-r prod.txt` must not
// report clean on the visible few while prod.txt's pins (and any poisoned one)
// go unseen and undisclosed.
type reqAccum struct {
	entries        []reqEntry
	unpinned       []string
	declared       []graph.DeclaredDep
	markerExcluded []string
	// unfollowed lists include directives that could NOT be read — a remote URL,
	// a path escaping the scan root, a missing or oversized file, or one past the
	// depth bound. Each is disclosed as a coverage gap so an unreadable include is
	// never confused with an absent one.
	unfollowed    []string
	hasProvenance bool
}

// parseRequirements reads a fully pinned requirements file, following its
// `-r`/`-c` includes within the containment root. Only `==` pins are treated as
// resolved; a loose specifier (>=, ~=, unpinned) is NOT resolved, because
// guessing which version a range would install is exactly the resolver
// reimplementation D-01 rules out. Unpinned lines are counted and reported.
func parseRequirements(path string, raw []byte, filePath, containRoot string) (*graph.Graph, error) {
	g := graph.New()
	root := rootNode(g, path)

	acc := &reqAccum{}
	var reader *securefs.Reader
	if containRoot != "" {
		reader, _ = securefs.NewReader(containRoot) // nil on a bad root: includes then disclose
	}
	// Scan by the concrete FILE path, not the (possibly directory) path used to
	// name the root: `-r`/`-c` targets resolve relative to the file that
	// references them, so fromDir must be the requirements file's own directory.
	visited := map[string]bool{}
	scanRequirementsFile(acc, reader, filePath, raw, visited, 0)

	// Non-canonical requirements siblings (requirements-dev.txt,
	// test-requirements.txt, …) in the same directory are a real install-time
	// surface that only an explicit `-r` reached before (OPU-13). Read them into
	// the same project root. `visited` carries over, so a sibling already pulled
	// in via `-r` is not read twice, and a securefs reader keeps every read
	// contained.
	scanSiblingRequirements(acc, reader, filepath.Dir(filePath), visited)

	if len(acc.entries) == 0 && len(acc.unpinned) == 0 && len(acc.unfollowed) == 0 {
		return nil, fmt.Errorf("pypi: %s contained no requirements", requirementsName)
	}

	// Nodes.
	byName := map[string]string{} // normalized name -> node ID
	for _, e := range acc.entries {
		id := purl.NewPyPI(e.name, e.version).String()
		attr := map[string]string{"pypi.source": requirementsName}
		if e.marker != "" {
			attr["pypi.marker"] = e.marker
		}
		g.AddNode(&graph.Node{
			ID: id, Ecosystem: "pypi", Name: purl.NormalizePyPI(e.name), Version: e.version,
			Attr: attr,
		})
		byName[purl.NormalizePyPI(e.name)] = id
	}

	// Edges from `# via` provenance; anything sourced from a -r/-c include or an
	// unknown parent hangs off the root as a direct dependency.
	for _, e := range acc.entries {
		id := byName[purl.NormalizePyPI(e.name)]
		linked := false
		for _, v := range e.vias {
			parent, ok := byName[purl.NormalizePyPI(v)]
			if !ok || parent == id {
				continue
			}
			g.AddEdge(parent, id, graph.EdgeDependsOn)
			linked = true
		}
		if !linked {
			g.AddEdge(root.ID, id, graph.EdgeDependsOn)
			if n := g.Get(id); n != nil {
				n.Direct = true
			}
		}
	}

	// Root-level facts are written into the existing root.Attr map (rootNode
	// always populates it) rather than replaced wholesale — several conditions
	// below can all be true for the same file (e.g. partially unpinned AND
	// fully flat), and a bare `root.Attr = map[string]string{...}` would drop
	// whichever fact was written first, including rootNode's own attributes.
	if root.Attr == nil {
		root.Attr = map[string]string{}
	}
	// Unpinned requirements and unfollowed includes are both coverage gaps: an
	// unpinned line has no resolved version, an unfollowed include has an unread
	// set of them. Both degrade coverage through the same channel so the scan
	// cannot read as a clean, complete tree while a referenced file went unread.
	disclose := append(append([]string{}, acc.unpinned...), acc.unfollowed...)
	if len(disclose) > 0 {
		sort.Strings(disclose)
		root.Attr[graph.AttrUnresolved] = strings.Join(disclose, ",")
		root.Attr[graph.AttrUnresolvedCount] = fmt.Sprintf("%d", len(disclose))
	}
	// Record the unpinned deps WITH their constraints so transitive expansion can
	// presume a version for each (the local root has no registry coordinate, so
	// the walk cannot fetch these from a registry — they must ride on the node).
	// Kept separate from AttrUnresolved, which stays the coverage disclosure.
	if len(acc.declared) > 0 {
		sort.Slice(acc.declared, func(i, j int) bool { return acc.declared[i].Name < acc.declared[j].Name })
		root.Attr[graph.AttrDeclaredDeps] = graph.EncodeDeclaredDeps(acc.declared)
	}
	if len(acc.markerExcluded) > 0 {
		sort.Strings(acc.markerExcluded)
		// Not folded into AttrUnresolved: these are deliberately excluded from
		// the coverage gate because their marker proves they never install on
		// this platform. The exclusion itself is still disclosed, not silent.
		root.Attr["pypi.marker_excluded"] = strings.Join(acc.markerExcluded, ",")
	}
	if !acc.hasProvenance && len(acc.entries) > 0 {
		// No line in the file contributed a `# via` parent at all — the same
		// "format records no inter-package relationships" situation
		// Pipfile.lock is in, just for a plain `pip freeze` requirements.txt
		// instead of a lockfile format.
		root.Attr[graph.AttrFlatResolution] = "pypi"
	}

	assignDepths(g, root.ID)
	return g, nil
}

// scanRequirementsFile scans one requirements file into acc, recursing into each
// `-r`/`-c` include it references. reader (nil when no containment root resolved)
// bounds and vets every include read; visited (keyed by canonical path) breaks
// cycles; depth bounds the chain.
func scanRequirementsFile(acc *reqAccum, reader *securefs.Reader, filePath string, raw []byte, visited map[string]bool, depth int) {
	if key := canonicalPath(filePath); key != "" {
		if visited[key] {
			return // already scanned this file — a cycle, or a diamond include
		}
		visited[key] = true
	}
	fromDir := filepath.Dir(filePath)

	// Strip a leading UTF-8 BOM: `pip freeze > requirements.txt` under Windows
	// PowerShell 5.1 (and any Notepad save) emits one, and strings.TrimSpace
	// does not remove U+FEFF — it is category Cf, not White_Space — so the
	// first dependency in the file would otherwise fail to parse.
	sc := bufio.NewScanner(strings.NewReader(strings.TrimPrefix(string(raw), "\uFEFF")))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	curIdx := -1 // index into acc.entries of the entry a `# via` line attaches to
	inVia := false
	for sc.Scan() {
		trimmed := strings.TrimSpace(sc.Text())
		if trimmed == "" {
			continue
		}

		// pip-compile provenance comments:
		//   # via
		//   #   -r requirements.in
		//   #   some-parent
		if strings.HasPrefix(trimmed, "#") {
			comment := strings.TrimSpace(strings.TrimPrefix(trimmed, "#"))
			switch {
			case comment == "via":
				inVia = true
			case strings.HasPrefix(comment, "via "):
				if curIdx >= 0 {
					if v := viaTarget(strings.TrimPrefix(comment, "via ")); v != "" {
						acc.entries[curIdx].vias = append(acc.entries[curIdx].vias, v)
						acc.hasProvenance = true
					}
				}
				inVia = false
			case inVia && curIdx >= 0:
				if v := viaTarget(comment); v != "" {
					acc.entries[curIdx].vias = append(acc.entries[curIdx].vias, v)
					acc.hasProvenance = true
				}
			}
			continue
		}
		inVia = false

		// An `-r`/`-c` include: follow it (the pinned versions a project split into
		// a separate file live here, and an attacker could hide a poisoned pin in
		// one). Everything the include declares is merged into the same project.
		if target, ok := includeTarget(trimmed); ok {
			followInclude(acc, reader, fromDir, target, visited, depth)
			continue
		}
		// Any other pip flag (--hash, -e, --index-url, …) is not a requirement.
		if strings.HasPrefix(trimmed, "-") {
			continue
		}

		// Strip inline hashes / continuations and trailing comments.
		body := trimmed
		if i := strings.Index(body, " --hash"); i >= 0 {
			body = body[:i]
		}
		body = strings.TrimSuffix(strings.TrimSpace(body), "\\")
		if i := strings.Index(body, " #"); i >= 0 {
			body = body[:i]
		}
		body = strings.TrimSpace(body)
		if body == "" {
			continue
		}

		name, version, pinned, marker := pep508.Split(body)
		_, specifier, _ := pep508.SplitSpecifier(body)
		if name == "" {
			// pep508.Split could not read this line as a requirement at all — a
			// bare URL or local path, a name violating PEP 508's grammar, a
			// stray fragment. That is a coverage gap, not an absent dependency,
			// so it is DISCLOSED rather than silently dropped (D-24).
			acc.unpinned = append(acc.unpinned, unparseableToken(body))
			continue
		}
		if !pinned {
			if marker != "" && pep508.ExcludesLinux(marker) {
				acc.markerExcluded = append(acc.markerExcluded, name)
			} else {
				acc.unpinned = append(acc.unpinned, name)
				// Keep the constraint (Split discards a range; SplitSpecifier
				// keeps it) so transitive expansion can presume a version rather
				// than leaving the dependency merely disclosed as unresolved.
				acc.declared = append(acc.declared, graph.DeclaredDep{Name: purl.NormalizePyPI(name), Constraint: specifier})
			}
			continue
		}
		acc.entries = append(acc.entries, reqEntry{name: name, version: version, marker: marker})
		curIdx = len(acc.entries) - 1
	}
	// A scan error (an over-long line hits the 4 MB buffer cap) bounds this file
	// but not the whole project — the lines already read stand, and the truncation
	// is disclosed like any unread include.
	if err := sc.Err(); err != nil {
		acc.unfollowed = append(acc.unfollowed, includeToken(filepath.Base(filePath), "unreadable: "+err.Error()))
	}
}

// followInclude resolves and reads one `-r`/`-c` target, recursing into it. An
// include that cannot be safely read — a remote URL, an escape of the scan root,
// a missing/oversized/non-regular file, or one past the depth bound — is
// disclosed as a coverage gap rather than read or silently dropped.
func followInclude(acc *reqAccum, reader *securefs.Reader, fromDir, target string, visited map[string]bool, depth int) {
	if low := strings.ToLower(target); strings.HasPrefix(low, "http://") || strings.HasPrefix(low, "https://") {
		acc.unfollowed = append(acc.unfollowed, includeToken(target, "remote URL"))
		return
	}
	if depth+1 > maxIncludeDepth {
		acc.unfollowed = append(acc.unfollowed, includeToken(target, "include depth exceeded"))
		return
	}
	if reader == nil {
		acc.unfollowed = append(acc.unfollowed, includeToken(target, "no containment root"))
		return
	}
	p := target
	if !filepath.IsAbs(p) {
		p = filepath.Join(fromDir, target)
	}
	data, err := reader.ReadFile(p)
	if err != nil {
		acc.unfollowed = append(acc.unfollowed, includeToken(target, includeReason(err)))
		return
	}
	scanRequirementsFile(acc, reader, p, data, visited, depth+1)
}

// includeReason maps a contained-read failure to a short disclosure reason.
func includeReason(err error) string {
	switch {
	case errors.Is(err, securefs.ErrOutsideRoot):
		return "outside scan root"
	case errors.Is(err, os.ErrNotExist):
		return "missing"
	case errors.Is(err, securefs.ErrTooLarge):
		return "too large"
	case errors.Is(err, securefs.ErrNotRegular):
		return "not a regular file"
	}
	return "unreadable"
}

// scanSiblingRequirements reads every non-canonical requirements file in dir
// (requirements-dev.txt, test-requirements.txt, …) into the same accumulator, so
// a split-requirements project's dev/test/CI dependency surface is covered
// rather than left to an explicit `-r` (OPU-13). visited carries the primary
// file and anything already pulled in via `-r`, so nothing is read twice; every
// read is contained by the securefs reader, and one that cannot be read is
// disclosed like an unfollowed include, never silently dropped (D-24).
func scanSiblingRequirements(acc *reqAccum, reader *securefs.Reader, dir string, visited map[string]bool) {
	if reader == nil {
		return // no containment root: cannot safely read siblings
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && isRequirementsFile(e.Name()) {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names) // determinism (D-13)
	for _, name := range names {
		p := filepath.Join(dir, name)
		if visited[canonicalPath(p)] {
			continue // the primary file, or a sibling already read via -r
		}
		data, err := reader.ReadFile(p)
		if err != nil {
			acc.unfollowed = append(acc.unfollowed, includeToken(name, includeReason(err)))
			continue
		}
		scanRequirementsFile(acc, reader, p, data, visited, 0)
	}
}

// includeTarget reports whether a line is a `-r`/`-c` (or `--requirement`/
// `--constraint`) include and returns its target path. pip accepts the argument
// separated by a space, an `=`, or — for the short forms — glued directly
// (`-rfile.txt`). A trailing inline comment is stripped.
func includeTarget(line string) (string, bool) {
	s := strings.TrimSpace(line)
	for _, pre := range []string{"--requirement", "--constraint"} {
		if !strings.HasPrefix(s, pre) {
			continue
		}
		rest := s[len(pre):]
		if rest == "" || (rest[0] != ' ' && rest[0] != '\t' && rest[0] != '=') {
			continue // "--requirements" (a different token) must not match
		}
		if arg := cleanIncludeArg(rest[1:]); arg != "" {
			return arg, true
		}
	}
	for _, pre := range []string{"-r", "-c"} {
		if !strings.HasPrefix(s, pre) {
			continue
		}
		rest := s[len(pre):]
		if rest == "" {
			continue // a bare "-r" with no argument is malformed; skip
		}
		if rest[0] == ' ' || rest[0] == '\t' || rest[0] == '=' {
			rest = rest[1:]
		}
		// else: glued form `-rfile.txt`; rest is already the argument.
		if arg := cleanIncludeArg(rest); arg != "" {
			return arg, true
		}
	}
	return "", false
}

// cleanIncludeArg trims an include target of surrounding space, quotes, and a
// trailing " #" comment.
func cleanIncludeArg(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, " #"); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	return strings.Trim(s, `"'`)
}

// includeToken renders an unfollowed include as one comma-free, length-bounded
// disclosure token for graph.AttrUnresolved (the same constraints
// unparseableToken documents).
func includeToken(target, reason string) string {
	t := strings.ReplaceAll(strings.TrimSpace(target), ",", " ")
	if r := []rune(t); len(r) > 50 {
		t = string(r[:50]) + "…"
	}
	return "<unfollowed-include: " + t + " (" + reason + ")>"
}

// canonicalPath resolves a file path to its symlink-free absolute form for cycle
// detection, falling back to the cleaned absolute path when it cannot be
// resolved (a not-yet-read top file), and to the input when even that fails.
func canonicalPath(p string) string {
	abs, err := filepath.Abs(p)
	if err != nil {
		return p
	}
	if canon, err := filepath.EvalSymlinks(abs); err == nil {
		return canon
	}
	return filepath.Clean(abs)
}

// viaTarget extracts a parent package name from a pip-compile `via` line,
// ignoring file references like "-r requirements.in".
func viaTarget(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || strings.HasPrefix(s, "-") {
		return ""
	}
	// "some-parent (setup.py)" -> "some-parent"
	if i := strings.IndexByte(s, ' '); i > 0 {
		s = s[:i]
	}
	return s
}

// ---- Pipfile.lock --------------------------------------------------------

type pipfileLock struct {
	Default map[string]pipfileEntry `json:"default"`
	Develop map[string]pipfileEntry `json:"develop"`
}

type pipfileEntry struct {
	Version string   `json:"version"` // e.g. "==2.31.0"
	Hashes  []string `json:"hashes"`
}

// parsePipfileLock reads a Pipfile.lock. It records no edges: the format lists
// a flat resolved set without provenance, so every entry hangs off the root.
// That is a real limitation of the format, recorded rather than invented.
func parsePipfileLock(path string, raw []byte) (*graph.Graph, error) {
	var lf pipfileLock
	if err := json.Unmarshal(raw, &lf); err != nil {
		return nil, fmt.Errorf("pypi: parsing %s: %w", pipfileLockName, err)
	}
	g := graph.New()
	root := rootNode(g, path)

	add := func(section string, m map[string]pipfileEntry) {
		names := make([]string, 0, len(m))
		for n := range m {
			names = append(names, n)
		}
		sort.Strings(names) // determinism (D-13)
		for _, name := range names {
			version := strings.TrimPrefix(strings.TrimSpace(m[name].Version), "==")
			if version == "" {
				continue
			}
			id := purl.NewPyPI(name, version).String()
			g.AddNode(&graph.Node{
				ID: id, Ecosystem: "pypi", Name: purl.NormalizePyPI(name), Version: version,
				Direct: true, Depth: 1,
				Attr: map[string]string{"pypi.source": pipfileLockName, "pypi.section": section},
			})
			g.AddEdge(root.ID, id, graph.EdgeDependsOn)
		}
	}
	add("default", lf.Default)
	add("develop", lf.Develop)

	if g.Len() == 1 {
		return nil, fmt.Errorf("pypi: %s contained no resolved packages", pipfileLockName)
	}

	// Record the format's limitation as a coverage fact (Decision D-24). Every
	// package here sits at depth 1 because Pipfile.lock does not express
	// inter-package relationships — not because the tree is genuinely one layer
	// deep. Without this the depth histogram silently implies the opposite.
	if root.Attr == nil {
		root.Attr = map[string]string{}
	}
	root.Attr[graph.AttrFlatResolution] = "pypi"

	assignDepths(g, root.ID)
	return g, nil
}

// ---- shared --------------------------------------------------------------

// assignDepths does a BFS from root, setting each node's shortest depth.
func assignDepths(g *graph.Graph, rootID string) {
	adj := map[string][]string{}
	for _, e := range g.Edges {
		if e.Type == graph.EdgeDependsOn {
			adj[e.From] = append(adj[e.From], e.To)
		}
	}
	depth := map[string]int{rootID: 0}
	seen := map[string]bool{rootID: true}
	queue := []string{rootID}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, next := range adj[cur] {
			if !seen[next] {
				seen[next] = true
				depth[next] = depth[cur] + 1
				queue = append(queue, next)
			}
		}
	}
	for id, d := range depth {
		if n := g.Get(id); n != nil {
			n.Depth = d
		}
	}
}
