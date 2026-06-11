package screenshot

import "testing"

func TestDefaults(t *testing.T) {
	o := Options{}
	defaults(&o)
	if o.WaitMs != 1500 || o.Width != 1280 || o.Height != 800 || o.TimeoutMs != 30000 {
		t.Fatalf("unexpected defaults: %+v", o)
	}

	o2 := Options{WaitMs: 500, Width: 640, Height: 480, TimeoutMs: 5000}
	defaults(&o2)
	if o2.WaitMs != 500 || o2.Width != 640 {
		t.Fatalf("defaults should not override explicit values: %+v", o2)
	}
}
