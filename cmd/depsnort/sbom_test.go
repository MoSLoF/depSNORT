package main

import (
	"bytes"
	"encoding/json"
	"runtime/debug"
	"strings"
	"testing"
)

func TestSBOMIsWellFormedCycloneDX(t *testing.T) {
	var buf bytes.Buffer
	if err := emitSBOM(&buf, false); err != nil {
		t.Fatalf("emitSBOM: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("SBOM is not valid JSON: %v", err)
	}
	if doc["bomFormat"] != "CycloneDX" {
		t.Errorf("bomFormat = %v, want CycloneDX", doc["bomFormat"])
	}
	if doc["specVersion"] != "1.5" {
		t.Errorf("specVersion = %v, want 1.5", doc["specVersion"])
	}
	if s, _ := doc["serialNumber"].(string); !strings.HasPrefix(s, "urn:uuid:") {
		t.Errorf("serialNumber = %q, want a urn:uuid:", s)
	}
	if _, ok := doc["components"]; !ok {
		t.Error("SBOM must always carry a components key — an empty list is itself a claim")
	}
}

// D-13: two runs over identical input produce identical bytes. An SBOM with a
// random serial or an embedded timestamp cannot be diffed across rebuilds, which
// is precisely what a consumer verifying a release wants to do.
func TestSBOMIsDeterministic(t *testing.T) {
	var a, b bytes.Buffer
	if err := emitSBOM(&a, false); err != nil {
		t.Fatal(err)
	}
	if err := emitSBOM(&b, false); err != nil {
		t.Fatal(err)
	}
	if a.String() != b.String() {
		t.Error("SBOM is not byte-reproducible across runs")
	}
}

// D-10, made machine-checkable. depSNORT claims zero third-party
// dependencies; the SBOM is generated from the module graph the linker actually
// embedded, so if that claim ever stops being true, this test fails rather than
// the README quietly becoming a lie.
func TestSBOMProvesZeroThirdPartyDependencies(t *testing.T) {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		t.Skip("no build info available")
	}
	doc := buildSBOM(bi, "v0.0.0-test")
	if len(doc.Components) != 0 {
		var names []string
		for _, c := range doc.Components {
			names = append(names, c.Name)
		}
		t.Errorf("the zero-dependency invariant (D-10) is broken; SBOM lists: %s",
			strings.Join(names, ", "))
	}
	// The main component must still be described, or the SBOM says nothing.
	if doc.Metadata.Component.Name == "" || doc.Metadata.Component.PURL == "" {
		t.Errorf("main component is not described: %+v", doc.Metadata.Component)
	}
}

// R-03. A release ships five platform binaries but only one can be run to
// generate an SBOM. A host-flavoured document attached to a darwin/arm64
// artifact would misstate it, so the release-scoped form omits host build
// settings and declares its scope instead of implying a platform it never
// inspected.
func TestReleaseScopedSBOMOmitsHostPlatform(t *testing.T) {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		t.Skip("no build info available")
	}
	rel := buildSBOMScoped(bi, "v1.2.3", true)
	host := buildSBOMScoped(bi, "v1.2.3", false)

	names := func(d cdxSBOM) map[string]string {
		m := map[string]string{}
		for _, p := range d.Metadata.Props {
			m[p.Name] = p.Value
		}
		return m
	}
	relProps, hostProps := names(rel), names(host)

	for _, k := range []string{"go:GOOS", "go:GOARCH", "go:GOAMD64"} {
		if _, bad := relProps[k]; bad {
			t.Errorf("release-scoped SBOM must not carry host-specific %s", k)
		}
	}
	if _, ok := relProps["depsnort:sbom-scope"]; !ok {
		t.Error("release-scoped SBOM must declare its scope explicitly")
	}
	// The host-scoped default still describes this binary precisely.
	if _, ok := hostProps["go:GOOS"]; !ok {
		t.Error("host-scoped SBOM should still record GOOS")
	}
	// Platform-independent facts survive in both.
	if _, ok := relProps["go:CGO_ENABLED"]; !ok {
		t.Error("CGO_ENABLED is platform-independent and should remain in the release SBOM")
	}
	// Both must still prove the dogfood invariant.
	if len(rel.Components) != 0 {
		t.Errorf("release SBOM lists third-party components: %+v", rel.Components)
	}
}

func TestStableSerialIsAUUIDv5(t *testing.T) {
	s := stableSerial("pkg:golang/ihbv.io/depsnort@v1.0.0")
	if !strings.HasPrefix(s, "urn:uuid:") {
		t.Fatalf("serial %q missing urn:uuid: prefix", s)
	}
	// Same input -> same serial; different input -> different serial.
	if s != stableSerial("pkg:golang/ihbv.io/depsnort@v1.0.0") {
		t.Error("serial is not stable for identical input")
	}
	if s == stableSerial("pkg:golang/ihbv.io/depsnort@v2.0.0") {
		t.Error("serial must differ across versions")
	}
	// UUID v5, RFC 4122 variant: the version nibble is at a fixed offset.
	hex := strings.TrimPrefix(s, "urn:uuid:")
	parts := strings.Split(hex, "-")
	if len(parts) != 5 {
		t.Fatalf("malformed UUID %q", hex)
	}
	if parts[2][0] != '5' {
		t.Errorf("UUID version nibble = %c, want 5", parts[2][0])
	}
}
