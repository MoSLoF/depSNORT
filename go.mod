module ihbv.io/depsnort

go 1.24

// depSNORT dogfoods its own posture (Decision D-10): the tool has ZERO
// third-party dependencies. Everything below is the Go standard library.
// If a `require` block ever appears here, it must be hash-pinned in go.sum and
// justified against the dogfood constraint in docs/DECISIONS.md.
