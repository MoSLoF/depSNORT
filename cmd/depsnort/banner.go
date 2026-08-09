package main

import (
	"os"
	"strings"
)

// bannerArt is "depSNORT" rendered in the figlet "block" font — block letters
// drawn in dashes, per the house style.
const bannerArt = `      _|                        _|_|_|  _|      _|    _|_|    _|_|_|    _|_|_|_|_|
  _|_|_|    _|_|    _|_|_|    _|        _|_|    _|  _|    _|  _|    _|      _|
_|    _|  _|_|_|_|  _|    _|    _|_|    _|  _|  _|  _|    _|  _|_|_|        _|
_|    _|  _|        _|    _|        _|  _|    _|_|  _|    _|  _|    _|      _|
  _|_|_|    _|_|_|  _|_|_|    _|_|_|    _|      _|    _|_|    _|    _|      _|
                    _|
                    _|`

// bannerSubtitle is the purple-team signature — a PowerShell assignment, since
// that is the dialect this shop thinks in.
const bannerSubtitle = `$global:Intent = 'Purple'`

// ANSI escapes. Bright red for the mark, bright magenta for the intent line.
const (
	ansiReset   = "\033[0m"
	ansiRed     = "\033[91m"
	ansiMagenta = "\033[95m"
)

// colorEnabled reports whether to emit ANSI color to f: honored only for a
// real terminal, and suppressed entirely when NO_COLOR is set (so piped output,
// SARIF, and CI logs never get escape codes).
func colorEnabled(f *os.File) bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// banner renders the depSNORT banner for the stream it will be written to:
// bright-red block letters over the purple-team intent line, color stripped
// when the destination is not a terminal.
func banner(f *os.File) string {
	color := colorEnabled(f)
	var b strings.Builder
	if color {
		b.WriteString(ansiRed)
	}
	b.WriteString(bannerArt)
	if color {
		b.WriteString(ansiReset)
	}
	b.WriteString("\n")
	if color {
		b.WriteString(ansiMagenta)
	}
	b.WriteString("  " + bannerSubtitle)
	if color {
		b.WriteString(ansiReset)
	}
	b.WriteString("\n")
	return b.String()
}
