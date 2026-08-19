package goproxy

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"ihbv.io/depsnort/internal/datasource"
)

type histFake struct {
	list  map[string][]string
	infos map[string]string // "module@version" -> Time
}

func (f *histFake) Do(req *http.Request) (*http.Response, error) {
	p := req.URL.Path
	body, status := "not found", 404
	if strings.HasSuffix(p, "/@v/list") {
		mod := deesc(strings.TrimSuffix(strings.TrimPrefix(p, "/"), "/@v/list"))
		if vs, ok := f.list[mod]; ok {
			body, status = strings.Join(vs, "\n"), 200
		}
	} else if strings.HasSuffix(p, ".info") {
		i := strings.Index(p, "/@v/")
		mod := deesc(strings.TrimPrefix(p[:i], "/"))
		ver := strings.TrimSuffix(p[i+4:], ".info")
		if t, ok := f.infos[mod+"@"+ver]; ok {
			body, status = `{"Version":"`+ver+`","Time":"`+t+`"}`, 200
		}
	}
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
}

func deesc(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '!' && i+1 < len(s) {
			b.WriteByte(s[i+1] - ('a' - 'A'))
			i++
		} else {
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

func TestHistoriesBuildsReleaseHistory(t *testing.T) {
	f := &histFake{
		list: map[string][]string{"github.com/foo/bar": {"v1.0.0", "v1.1.0", "v1.2.0"}},
		infos: map[string]string{
			"github.com/foo/bar@v1.0.0": "2020-01-01T00:00:00Z",
			"github.com/foo/bar@v1.1.0": "2021-06-01T00:00:00Z",
			"github.com/foo/bar@v1.2.0": "2023-03-15T00:00:00Z",
		},
	}
	c := New(datasource.NewCache(t.TempDir(), time.Hour), false)
	c.HTTP = f
	if c.Ecosystem() != "gomod" {
		t.Errorf("ecosystem = %q", c.Ecosystem())
	}
	h, err := c.Histories(context.Background(), []string{"github.com/foo/bar"})
	if err != nil {
		t.Fatal(err)
	}
	rh := h["github.com/foo/bar"]
	if rh == nil || len(rh.Releases) != 3 {
		t.Fatalf("releases = %v", rh)
	}
	// sorted oldest->newest, publish times preserved
	if rh.Releases[0].Version != "v1.0.0" || rh.Releases[2].Version != "v1.2.0" {
		t.Errorf("order wrong: %+v", rh.Releases)
	}
	if rh.Releases[0].Published.Year() != 2020 || rh.Releases[2].Published.Year() != 2023 {
		t.Errorf("publish times wrong: %+v", rh.Releases)
	}
}
