package clojure

import "strings"

// Minimal Clojure-source scanning utilities shared by the project.clj and
// deps.edn readers. This is NOT an EDN parser — depSNORT is zero-dependency
// and these two manifests need only three structural facts: where a line
// comment ends, where a string literal ends, and where a balanced []/{}/( )
// form ends. Everything subtler (tagged literals, metadata, namespaced maps)
// is treated as opaque text; a dependency entry the scanner cannot read with
// confidence is disclosed as unresolved, never guessed (D-24 discipline).

// stripCljComments removes `;` line comments, respecting string literals so a
// semicolon inside a version or URL string is not read as a comment opener.
// String contents are preserved verbatim — the version pins live there.
func stripCljComments(src string) string {
	var b strings.Builder
	b.Grow(len(src))
	i, n := 0, len(src)
	for i < n {
		switch src[i] {
		case '"':
			end := scanCljString(src, i)
			b.WriteString(src[i:end])
			i = end
		case '\\':
			// A character literal (\a, \newline, \;) — copy the backslash and
			// the next byte so \; is not read as a comment opener.
			b.WriteByte(src[i])
			i++
			if i < n {
				b.WriteByte(src[i])
				i++
			}
		case ';':
			for i < n && src[i] != '\n' {
				i++
			}
		default:
			b.WriteByte(src[i])
			i++
		}
	}
	return b.String()
}

// scanCljString returns the index just past the string literal opening at i.
func scanCljString(s string, i int) int {
	n := len(s)
	i++ // past the opening quote
	for i < n {
		switch s[i] {
		case '\\':
			i += 2
		case '"':
			return i + 1
		default:
			i++
		}
	}
	return n
}

// scanBalanced returns the index just past the balanced form whose opening
// bracket sits at i, honoring all three bracket kinds and string literals. If
// the form never closes, it returns len(s) — the caller's read of a truncated
// form then falls out as unresolved entries, not as an invented close.
func scanBalanced(s string, i int) int {
	n := len(s)
	depth := 0
	for i < n {
		switch s[i] {
		case '"':
			i = scanCljString(s, i)
			continue
		case '\\':
			i += 2
			continue
		case '[', '{', '(':
			depth++
		case ']', '}', ')':
			depth--
			if depth == 0 {
				return i + 1
			}
		}
		i++
	}
	return n
}

// skipWS advances past whitespace and commas (whitespace in Clojure).
func skipWS(s string, i int) int {
	for i < len(s) {
		switch s[i] {
		case ' ', '\t', '\n', '\r', ',':
			i++
		default:
			return i
		}
	}
	return i
}

// readSymbol reads a Clojure symbol or keyword starting at i and returns it
// with the index just past it. Symbols end at whitespace, a comma, a bracket,
// or a quote.
func readSymbol(s string, i int) (string, int) {
	start := i
	for i < len(s) {
		switch s[i] {
		case ' ', '\t', '\n', '\r', ',', '[', ']', '{', '}', '(', ')', '"':
			return s[start:i], i
		}
		i++
	}
	return s[start:i], i
}

// readString reads the string literal opening at i and returns its contents
// (escapes left verbatim — a Maven version has none) with the index past it.
func readString(s string, i int) (string, int) {
	end := scanCljString(s, i)
	body := s[i:end]
	body = strings.TrimPrefix(body, `"`)
	body = strings.TrimSuffix(body, `"`)
	return body, end
}
