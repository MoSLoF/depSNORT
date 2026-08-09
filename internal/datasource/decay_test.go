package datasource

import (
	"testing"
	"time"
)

func TestDecayCurve(t *testing.T) {
	if d := Decay(0, DefaultHalfLife); d != 1 {
		t.Errorf("age 0 -> %v, want 1", d)
	}
	if d := Decay(DefaultHalfLife, DefaultHalfLife); d < 0.49 || d > 0.51 {
		t.Errorf("one half-life -> %v, want ~0.5", d)
	}
	if d := Decay(2*DefaultHalfLife, DefaultHalfLife); d < 0.24 || d > 0.26 {
		t.Errorf("two half-lives -> %v, want ~0.25", d)
	}
	if d := Decay(20*DefaultHalfLife, DefaultHalfLife); d > 0.0001 {
		t.Errorf("twenty half-lives -> %v, want ~0", d)
	}
}

// Decay is derived from time.Now(), so at full precision two scans milliseconds
// apart produced different values and broke byte-reproducible output (D-09).
// Quantizing age to whole days fixes that: any two moments within the same day
// must yield exactly the same multiplier.
func TestDecayIsQuantizedToWholeDays(t *testing.T) {
	base := 45 * 24 * time.Hour
	want := Decay(base, DefaultHalfLife)
	for _, jitter := range []time.Duration{
		time.Nanosecond, time.Millisecond, time.Second,
		time.Minute, time.Hour, 23 * time.Hour,
	} {
		if got := Decay(base+jitter, DefaultHalfLife); got != want {
			t.Errorf("jitter %v changed decay: %v != %v", jitter, got, want)
		}
	}
	// Crossing a day boundary SHOULD change it — quantization must not flatten
	// the curve into uselessness.
	if Decay(base+24*time.Hour, DefaultHalfLife) == want {
		t.Error("crossing a full day should change the decay value")
	}
}

func TestDecayHandlesDegenerateHalfLife(t *testing.T) {
	if d := Decay(time.Hour, 0); d <= 0 || d > 1 {
		t.Errorf("zero half-life should fall back to the default, got %v", d)
	}
	if d := Decay(-time.Hour, DefaultHalfLife); d != 1 {
		t.Errorf("negative age -> %v, want 1", d)
	}
}
