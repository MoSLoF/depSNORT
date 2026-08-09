package builtin

// Known-legitimate packages: real, established names that happen to sit within
// typosquat distance of a popular package and must never be flagged.
//
// This list is EVIDENCE-DRIVEN, not speculative. Every entry below was an actual
// false positive observed in a scan of a real 58-repo workspace. Adding a name
// here is a claim that the package is genuinely well-known — so entries should
// come from observed false positives, not from guessing.
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
	"motion": {},
	// vs "bcrypt"
	"crypt": {},
	// vs "through2"
	"through": {},
	// vs "eslint"
	"tslint": {}, "eslintrc": {},
	// vs "commander"
	"commondir": {}, "commands": {},
	// vs "util"
	"utils": {},
	// vs "consola"
	"console": {},
	// vs "prisma"
	"prism": {},
	// vs "passport"
	"password": {},
	// vs "inquirer"
	"inquire": {},
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
