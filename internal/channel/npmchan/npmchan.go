// Package npmchan is npm's acquisition-channel Spec: the ~120 lines of
// ecosystem knowledge the shared resolver needs, and nothing else.
//
// Everything policy-shaped — what an alternate endpoint means, whether it
// degrades coverage, whether it gates — lives in internal/channel and the check
// stage. This file knows only that npm reads .npmrc, that a scope line is
// spelled "@scope:registry=", and that overrides live in package.json.
package npmchan

import (
	"encoding/json"
	"net/url"
	"path/filepath"
	"strings"

	"ihbv.io/depsnort/internal/channel"
)

// Spec implements channel.Spec for npm.
type Spec struct{}

func (Spec) Ecosystem() string { return "npm" }

// ConfigPaths is most-specific-first: the project .npmrc outranks the user's,
// and package.json carries `overrides`.
func (Spec) ConfigPaths(dir string) []string {
	return []string{
		filepath.Join(dir, ".npmrc"),
		filepath.Join(dir, "package.json"),
	}
}

func (Spec) Canonical(host string) bool {
	return host == "registry.npmjs.org"
}

// Match: "" is the default-registry line and matches every package; a scope
// pattern matches only names inside that scope. No globbing — npm has none, and
// inventing one here would widen a route past what npm would actually do.
func (Spec) Match(pattern, name string) bool {
	if pattern == "" {
		return true
	}
	return strings.HasPrefix(name, pattern)
}

func (s Spec) ParseConfig(path string, data []byte) (channel.Config, error) {
	if filepath.Base(path) == "package.json" {
		return s.parsePackageJSON(path, data)
	}
	return s.parseNpmrc(path, data)
}

// parseNpmrc reads the INI-ish subset npm actually uses for routing:
//
//	registry=https://registry.npmjs.org/
//	@acme:registry=https://npm.acme.internal/
func (Spec) parseNpmrc(path string, data []byte) (channel.Config, error) {
	var cfg channel.Config
	for i, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key, val = strings.TrimSpace(key), strings.TrimSpace(val)

		var pattern string
		switch {
		case key == "registry":
			pattern = "" // applies to everything
		case strings.HasSuffix(key, ":registry") && strings.HasPrefix(key, "@"):
			pattern = strings.TrimSuffix(key, ":registry") + "/"
		default:
			continue // auth tokens, cache paths, etc. are not routing
		}

		host := hostOf(val)
		if host == "" {
			continue // an unparseable endpoint is not a route; the file still
			// parsed, so this is silence, not a gap
		}
		cfg.Routes = append(cfg.Routes, channel.Route{
			Pattern:  pattern,
			Endpoint: host,
			Source:   channel.Location{File: path, Line: i + 1},
		})
	}
	return cfg, nil
}

// parsePackageJSON reads `overrides` — npm's silent coordinate rewrite. Only
// the flat form is read here; the nested form is a tree of the same shape and
// is left for the real implementation.
func (Spec) parsePackageJSON(path string, data []byte) (channel.Config, error) {
	var pkg struct {
		Overrides map[string]json.RawMessage `json:"overrides"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		// package.json bears on routing, so a parse failure is a GAP, not a
		// zero result: the caller marks affected nodes EndpointUnknown.
		return channel.Config{}, err
	}
	var cfg channel.Config
	for name, raw := range pkg.Overrides {
		var with string
		if json.Unmarshal(raw, &with) != nil {
			with = "<nested>"
		}
		cfg.Substitutions = append(cfg.Substitutions, channel.Substitution{
			Name:   name,
			With:   with,
			Source: channel.Location{File: path},
		})
	}
	return cfg, nil
}

func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

var _ channel.Spec = Spec{}
