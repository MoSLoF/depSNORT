package npmreg

import (
	"encoding/json"
	"testing"
)

// Regression for the Kibana live-fire: joi 0.1.x packuments store CONFIG OBJECTS
// under "scripts" (blanket, travis-cov — a 2013-era habit). A strict
// map[string]string aborted the whole packument unmarshal on such an entry,
// degrading npm-registry coverage for every version of the package. The tolerant
// the tolerant map must parse it: keep string-valued script bodies, drop object values.
func TestPackumentTolerantScripts(t *testing.T) {
	raw := []byte(`{
	  "name": "joi",
	  "versions": {
	    "0.1.0": {
	      "scripts": {
	        "postinstall": "node build.js",
	        "blanket": {"onlyCwd": true, "pattern": "//x"},
	        "travis-cov": {"threshold": 100}
	      }
	    },
	    "1.0.0": {
	      "scripts": {"test": "mocha"}
	    }
	  }
	}`)

	var p packument
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatalf("object-valued scripts must not abort the packument parse: %v", err)
	}

	v010, ok := p.Versions["0.1.0"]
	if !ok {
		t.Fatal("version 0.1.0 missing (whole packument likely failed to parse)")
	}
	// The real string script survives; the config-object entries are dropped.
	if v010.Scripts["postinstall"] != "node build.js" {
		t.Errorf("string script body lost: %v", v010.Scripts)
	}
	if _, present := v010.Scripts["blanket"]; present {
		t.Error("object-valued 'blanket' should have been dropped, not kept")
	}
	if _, present := v010.Scripts["travis-cov"]; present {
		t.Error("object-valued 'travis-cov' should have been dropped, not kept")
	}
	// A later, clean version still parses normally.
	if p.Versions["1.0.0"].Scripts["test"] != "mocha" {
		t.Errorf("clean version scripts not parsed: %v", p.Versions["1.0.0"].Scripts)
	}

	// The install-hook extraction still works over the surviving string bodies.
	if hooks := installHooksOf(v010.Scripts); len(hooks) != 1 || hooks[0] != "postinstall" {
		t.Errorf("installHooksOf(surviving scripts) = %v, want [postinstall]", hooks)
	}
}

// Regression for the Kibana follow-up: a packument "time" map with a stray
// object value (seen on package-a) must not abort the whole packument parse —
// the string timestamps survive, the junk is dropped. Same tolerant type as
// scripts (tolerantStrMap).
func TestPackumentTolerantTime(t *testing.T) {
	raw := []byte(`{
	  "name": "package-a",
	  "time": {
	    "created": "2020-01-01T00:00:00.000Z",
	    "1.0.0": "2020-01-02T00:00:00.000Z",
	    "modified": {"unexpected": "object"}
	  },
	  "versions": { "1.0.0": {} }
	}`)
	var p packument
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatalf("object-valued time entry must not abort the packument parse: %v", err)
	}
	if p.Time["1.0.0"] != "2020-01-02T00:00:00.000Z" {
		t.Errorf("string timestamp lost: %v", p.Time)
	}
	if _, present := p.Time["modified"]; present {
		t.Error("object-valued time entry should have been dropped")
	}
	if _, ok := p.Versions["1.0.0"]; !ok {
		t.Error("versions should still parse after a bad time entry")
	}
}
