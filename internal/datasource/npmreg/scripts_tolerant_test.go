package npmreg

import (
	"encoding/json"
	"testing"
)

// Regression for the Kibana live-fire: joi 0.1.x packuments store CONFIG OBJECTS
// under "scripts" (blanket, travis-cov — a 2013-era habit). A strict
// map[string]string aborted the whole packument unmarshal on such an entry,
// degrading npm-registry coverage for every version of the package. The tolerant
// scriptMap must parse it: keep string-valued script bodies, drop object values.
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
