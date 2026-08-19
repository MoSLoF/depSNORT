package builtin

// Known-legitimate packages: real, established names that happen to sit within
// typosquat distance of a popular package and must never be flagged.
//
// This list is EVIDENCE-DRIVEN, not speculative. Every entry below was an actual
// false positive observed in a real scan — the original 58-repo workspace, and
// later kibana's full tree once yarn.lock support made it visible (OPU-09).
// Adding a name here is a claim that the package is genuinely well-known — so
// entries come from observed false positives, not from guessing.
//
// Why a curated list rather than a popularity/age signal: distinguishing an
// established package from a squat by reputation needs per-candidate registry
// data (download counts, publish age), i.e. a network call. VC-006 is
// deliberately static — embedded corpus plus edit distance, no network — so it
// stays deterministic and air-gap-capable (D-09). A reputation gate is a real
// improvement but belongs as a separate opt-in enrichment (like -depsdev for the
// asserted tier), never baked into this check; until then the exonerated set is
// curated from evidence.
//
// The distinction from the popular corpus matters: `popularNpm` is the set of
// names a squat would IMITATE (the targets), while this is the set of names that
// are self-evidently real (the exonerated). A package can be the second without
// being worth listing as the first.

var legitimateNpm = map[string]struct{}{
	// vs "react"
	"preact": {}, "redact": {},
	// vs "colors"
	"color": {}, "colord": {},
	// vs "emotion"
	"motion": {}, "emoticon": {},
	// vs "bcrypt"
	"crypt": {},
	// vs "through2"
	"through": {},
	// vs "eslint"
	"tslint": {}, "eslintrc": {},
	// vs "commander"
	"commondir": {}, "commands": {},
	// vs "util"
	"utils": {}, "utila": {},
	// vs "consola"
	"console": {},
	// vs "prisma"
	"prism": {},
	// vs "passport"
	"password": {},
	// vs "inquirer"
	"inquire": {}, "enquirer": {},
	// vs "semver"
	"server": {},
	// vs "ts-node"
	"fs-node": {},
	// vs "babel-core"
	"table-core": {}, "babel__core": {},
	// vs "react-dom"
	"react-zdog": {},
}

var legitimatePyPI = map[string]struct{}{
	"scapy":   {}, // vs scipy — packet manipulation, entirely unrelated
	"unicorn": {}, // vs uvicorn — the CPU emulator
	"mkdoc":   {}, // vs mkdocs
}

// isKnownLegitimate reports whether a bare package name is a known-real package
// that must not be treated as a squat. Only npm and PyPI have curated
// allowlists; other ecosystems return false (no observed false positives yet).
func isKnownLegitimate(ecosystem, bare string) bool {
	switch ecosystem {
	case "npm":
		_, ok := legitimateNpm[bare]
		return ok
	case "pypi":
		_, ok := legitimatePyPI[bare]
		return ok
	default:
		return false
	}
}
