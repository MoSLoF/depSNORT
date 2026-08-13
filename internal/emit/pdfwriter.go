package emit

import (
	"bytes"
	"fmt"
	"strings"
)

// A minimal PDF 1.4 writer, standard library only.
//
// Generating PDFs normally means pulling in a library, but depSNORT ships
// zero third-party dependencies on purpose (Decision D-10) — buying a PDF
// package to print a supply-chain report would undercut the tool's own thesis.
// PDF's text-and-operators core is small enough to write directly, so this
// implements just what a report needs: base-14 fonts (no embedding), text
// placement, wrapping, rules, and filled rectangles.
//
// Output is deterministic: no /CreationDate and no wall-clock anywhere, so two
// scans of identical data produce identical bytes (Decision D-13).

const (
	pageWidth   = 595.28 // A4 portrait, points
	pageHeight  = 841.89
	marginLeft  = 48.0
	marginRight = 48.0
	marginTop   = 54.0
	marginBot   = 54.0
	contentW    = pageWidth - marginLeft - marginRight
)

// font identifiers mapped to base-14 fonts in the resource dictionary.
const (
	fontRegular = "F1" // Helvetica
	fontBold    = "F2" // Helvetica-Bold
	fontMono    = "F3" // Courier
)

// rgb is a fill colour in 0..1 space.
type rgb struct{ R, G, B float64 }

var (
	colInk     = rgb{0.08, 0.10, 0.13}
	colMuted   = rgb{0.42, 0.46, 0.52}
	colFaint   = rgb{0.62, 0.66, 0.72}
	colRule    = rgb{0.85, 0.87, 0.90}
	colBlock   = rgb{0.78, 0.09, 0.29}
	colGate    = rgb{0.66, 0.35, 0.05}
	colAdvis   = rgb{0.20, 0.44, 0.55}
	colClean   = rgb{0.12, 0.48, 0.30}
	colPanelBg = rgb{0.96, 0.97, 0.98}
)

// pdfPage accumulates a single page's content stream.
type pdfPage struct {
	buf bytes.Buffer
	y   float64 // current baseline cursor, measured from the page bottom
}

// pdfDoc builds a multi-page document.
type pdfDoc struct {
	pages []*pdfPage
	cur   *pdfPage
}

func newPDFDoc() *pdfDoc {
	d := &pdfDoc{}
	d.newPage()
	return d
}

func (d *pdfDoc) newPage() {
	p := &pdfPage{y: pageHeight - marginTop}
	d.pages = append(d.pages, p)
	d.cur = p
}

// space ensures h points remain on the current page, starting a new one if not.
func (d *pdfDoc) space(h float64) {
	if d.cur.y-h < marginBot {
		d.newPage()
	}
}

// text draws a single line and advances the cursor by lead.
func (d *pdfDoc) text(s string, font string, size float64, c rgb, indent, lead float64) {
	d.space(lead)
	fmt.Fprintf(&d.cur.buf, "BT /%s %.1f Tf %.3f %.3f %.3f rg %.2f %.2f Td (%s) Tj ET\n",
		font, size, c.R, c.G, c.B, marginLeft+indent, d.cur.y, escapePDF(s))
	d.cur.y -= lead
}

// wrapped draws text wrapped to the content width, honouring an indent.
func (d *pdfDoc) wrapped(s string, font string, size float64, c rgb, indent, lead float64) {
	for _, line := range wrapText(s, size, contentW-indent) {
		d.text(line, font, size, c, indent, lead)
	}
}

// rule draws a horizontal line and advances past it.
func (d *pdfDoc) rule(c rgb, thickness, gapBefore, gapAfter float64) {
	d.space(gapBefore + gapAfter + thickness)
	d.cur.y -= gapBefore
	fmt.Fprintf(&d.cur.buf, "%.3f %.3f %.3f RG %.2f w %.2f %.2f m %.2f %.2f l S\n",
		c.R, c.G, c.B, thickness, marginLeft, d.cur.y, pageWidth-marginRight, d.cur.y)
	d.cur.y -= gapAfter
}

// rect fills a rectangle sitting just under the current baseline — used for the
// small accent bars beside findings and table rows.
func (d *pdfDoc) rect(x, w, h float64, c rgb) {
	d.rectAt(x, w, h, -h+3, c)
}

// rectAt fills a rectangle whose BOTTOM edge sits bottomOffset points from the
// current baseline. Panels that sit *behind* text need a negative offset around
// a third of their height, so the baseline lands inside the box rather than on
// its top edge.
func (d *pdfDoc) rectAt(x, w, h, bottomOffset float64, c rgb) {
	fmt.Fprintf(&d.cur.buf, "%.3f %.3f %.3f rg %.2f %.2f %.2f %.2f re f\n",
		c.R, c.G, c.B, x, d.cur.y+bottomOffset, w, h)
}

// gap advances the cursor without drawing.
func (d *pdfDoc) gap(h float64) {
	d.space(h)
	d.cur.y -= h
}

// escapePDF escapes text for a PDF literal string. Non-ASCII is replaced rather
// than emitted raw: base-14 fonts use WinAnsi and a stray byte would render as
// garbage. Package names and advisory IDs are ASCII in practice.
func escapePDF(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '\\':
			b.WriteString(`\\`)
		case r == '(':
			b.WriteString(`\(`)
		case r == ')':
			b.WriteString(`\)`)
		case r == '\n' || r == '\r' || r == '\t':
			b.WriteByte(' ')
		case r < 32 || r > 126:
			// Map the few typographic characters the report uses; drop the rest.
			switch r {
			case '—', '–':
				b.WriteByte('-')
			case '“', '”':
				b.WriteByte('"')
			case '‘', '’':
				b.WriteByte('\'')
			case '…':
				b.WriteString("...")
			case '≈':
				b.WriteByte('~')
			case '→':
				b.WriteString("->")
			default:
				b.WriteByte('?')
			}
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// charWidth approximates Helvetica advance width as a fraction of em. Exact
// metrics would need the AFM tables; this is close enough for wrapping and
// keeps the writer dependency-free.
func charWidth(r rune) float64 {
	switch {
	case r == ' ':
		return 0.278
	case r == 'i' || r == 'l' || r == 'j' || r == '.' || r == ',' || r == '\'' || r == '|':
		return 0.24
	case r == 'm' || r == 'w' || r == 'M' || r == 'W':
		return 0.85
	case r >= 'A' && r <= 'Z':
		return 0.68
	default:
		return 0.53
	}
}

// textWidth estimates rendered width in points.
func textWidth(s string, size float64) float64 {
	var w float64
	for _, r := range s {
		w += charWidth(r)
	}
	return w * size
}

// wrapText breaks s into lines that fit maxW at the given size. Over-long
// single tokens (advisory ID runs, URLs) are hard-split rather than allowed to
// overflow the margin.
func wrapText(s string, size, maxW float64) []string {
	words := strings.Fields(s)
	if len(words) == 0 {
		return []string{""}
	}
	var lines []string
	cur := ""
	for _, w := range words {
		cand := w
		if cur != "" {
			cand = cur + " " + w
		}
		if textWidth(cand, size) <= maxW {
			cur = cand
			continue
		}
		if cur != "" {
			lines = append(lines, cur)
		}
		for textWidth(w, size) > maxW {
			cut := len(w)
			for cut > 1 && textWidth(w[:cut], size) > maxW {
				cut--
			}
			lines = append(lines, w[:cut])
			w = w[cut:]
		}
		cur = w
	}
	if cur != "" {
		lines = append(lines, cur)
	}
	return lines
}

// truncateRunes caps s at n characters, appending an ellipsis. Used for
// monospace columns, where character count IS width and padding with %-Ns only
// aligns if the value never exceeds N.
func truncateRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	if n <= 3 {
		return string(r[:n])
	}
	return string(r[:n-3]) + "..."
}

// truncate shortens s to fit maxW, appending an ellipsis.
func truncateToWidth(s string, size, maxW float64) string {
	if textWidth(s, size) <= maxW {
		return s
	}
	for len(s) > 1 {
		s = s[:len(s)-1]
		if textWidth(s+"...", size) <= maxW {
			return s + "..."
		}
	}
	return s
}

// render assembles the object graph and returns the complete PDF bytes.
func (d *pdfDoc) render(title string) []byte {
	var objects []string

	nPages := len(d.pages)
	// Object numbering: 1 catalog, 2 pages, 3..(2+n) page objects,
	// then n content streams, then 3 fonts.
	firstPage := 3
	firstContent := firstPage + nPages
	firstFont := firstContent + nPages

	// 1: catalog
	objects = append(objects, "<< /Type /Catalog /Pages 2 0 R >>")

	// 2: page tree
	var kids strings.Builder
	for i := 0; i < nPages; i++ {
		fmt.Fprintf(&kids, "%d 0 R ", firstPage+i)
	}
	objects = append(objects, fmt.Sprintf(
		"<< /Type /Pages /Count %d /Kids [%s] >>", nPages, strings.TrimSpace(kids.String())))

	// page objects
	for i := 0; i < nPages; i++ {
		objects = append(objects, fmt.Sprintf(
			"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 %.2f %.2f] "+
				"/Resources << /Font << /%s %d 0 R /%s %d 0 R /%s %d 0 R >> >> "+
				"/Contents %d 0 R >>",
			pageWidth, pageHeight,
			fontRegular, firstFont, fontBold, firstFont+1, fontMono, firstFont+2,
			firstContent+i))
	}

	// content streams
	for i := 0; i < nPages; i++ {
		body := d.pages[i].buf.String()
		objects = append(objects, fmt.Sprintf(
			"<< /Length %d >>\nstream\n%s\nendstream", len(body), body))
	}

	// fonts (base-14, no embedding)
	for _, name := range []string{"Helvetica", "Helvetica-Bold", "Courier"} {
		objects = append(objects, fmt.Sprintf(
			"<< /Type /Font /Subtype /Type1 /BaseFont /%s /Encoding /WinAnsiEncoding >>", name))
	}

	var out bytes.Buffer
	out.WriteString("%PDF-1.4\n")
	offsets := make([]int, len(objects)+1)
	for i, body := range objects {
		offsets[i+1] = out.Len()
		fmt.Fprintf(&out, "%d 0 obj\n%s\nendobj\n", i+1, body)
	}
	xref := out.Len()
	fmt.Fprintf(&out, "xref\n0 %d\n0000000000 65535 f \n", len(objects)+1)
	for i := 1; i <= len(objects); i++ {
		fmt.Fprintf(&out, "%010d 00000 n \n", offsets[i])
	}
	// No /CreationDate: a timestamp would make output non-reproducible (D-13).
	fmt.Fprintf(&out,
		"trailer\n<< /Size %d /Root 1 0 R /Info << /Title (%s) /Producer (depSNORT) >> >>\nstartxref\n%d\n%%%%EOF\n",
		len(objects)+1, escapePDF(title), xref)
	return out.Bytes()
}
