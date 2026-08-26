package goproxy

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

// D-143: the response cap was applied with a bare io.LimitReader. Both consumers
// of get() parse line-oriented text — @v/list is newline-separated versions,
// .mod is go.mod source — not JSON, so a truncated read does not fail to parse
// the way a cut-off JSON document would. An oversize list came back SHORT and
// with err == nil, and the entry at the cut was a fragment of a version string
// that was never published: truncation manufacturing data, not merely losing it.

type d143Fake struct {
	body   string
	status int
	seen   string
}

func (f *d143Fake) Do(req *http.Request) (*http.Response, error) {
	f.seen = req.URL.Path
	st := f.status
	if st == 0 {
		st = 200
	}
	return &http.Response{
		StatusCode: st,
		Body:       io.NopCloser(strings.NewReader(f.body)),
		Header:     http.Header{},
	}, nil
}

// d143List builds a newline-separated version list of at least n bytes.
func d143List(n int) string {
	var b strings.Builder
	for i := 0; b.Len() < n; i++ {
		b.WriteString("v1.")
		b.WriteString(itoaD143(i))
		b.WriteString(".0\n")
	}
	return b.String()
}

func itoaD143(i int) string {
	if i == 0 {
		return "0"
	}
	var d []byte
	for i > 0 {
		d = append([]byte{byte('0' + i%10)}, d...)
		i /= 10
	}
	return string(d)
}

func TestD143OversizeVersionListIsAGapNotAShortAnswer(t *testing.T) {
	f := &d143Fake{body: d143List(maxResponseSize + 4096)}
	c := &Client{HTTP: f}
	got, err := c.Versions(context.Background(), "example.invalid/mod")
	if err == nil {
		t.Fatalf("an oversize list must be an error, not a silently short list of %d", len(got))
	}
	if !strings.Contains(err.Error(), "byte limit") {
		t.Errorf("error should name the limit, got %v", err)
	}
	if len(got) != 0 {
		t.Errorf("a refused read must return nothing, got %d versions", len(got))
	}
}

// TestD143ExactlyAtCapIsNotOversize is the boundary the +1 read exists to get
// right: a body of exactly maxResponseSize bytes was received IN FULL, and
// rejecting it would turn a complete answer into a gap.
func TestD143ExactlyAtCapIsNotOversize(t *testing.T) {
	body := d143List(maxResponseSize)
	// Trim to exactly the cap on a line boundary so the list stays well-formed.
	body = body[:maxResponseSize]
	if i := strings.LastIndexByte(body, '\n'); i >= 0 {
		body = body[:i+1] + strings.Repeat(" ", maxResponseSize-i-1)
	}
	if len(body) != maxResponseSize {
		t.Fatalf("fixture is %d bytes, want exactly %d", len(body), maxResponseSize)
	}
	c := &Client{HTTP: &d143Fake{body: body}}
	got, err := c.Versions(context.Background(), "example.invalid/mod")
	if err != nil {
		t.Fatalf("a body of exactly the cap was fully received; got error %v", err)
	}
	if len(got) == 0 {
		t.Error("expected the full version list")
	}
}

func TestD143OversizeModFileIsAGap(t *testing.T) {
	var b strings.Builder
	b.WriteString("module example.invalid/mod\n\nrequire (\n")
	for b.Len() < maxResponseSize+4096 {
		b.WriteString("\texample.invalid/dep v1.0.0\n")
	}
	b.WriteString(")\n")
	c := &Client{HTTP: &d143Fake{body: b.String()}}
	raw, ok, err := c.ModFile(context.Background(), "example.invalid/mod", "v1.0.0")
	if err == nil {
		t.Fatalf("an oversize go.mod must be an error, not a require block silently missing its tail (got ok=%v, %d bytes)", ok, len(raw))
	}
	if ok {
		t.Error("a refused read must not report ok")
	}
}

// TestD143OrdinaryListIsUnaffected is the shape every real module has.
func TestD143OrdinaryListIsUnaffected(t *testing.T) {
	c := &Client{HTTP: &d143Fake{body: "v1.0.0\nv1.1.0\nv2.0.0\n"}}
	got, err := c.Versions(context.Background(), "example.invalid/mod")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[2] != "v2.0.0" {
		t.Errorf("got %v, want the three published versions", got)
	}
}
