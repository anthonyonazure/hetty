package wordlists

import "testing"

func TestNamesAndGet(t *testing.T) {
	names := Names()
	if len(names) < 5 {
		t.Fatalf("expected several lists, got %d", len(names))
	}

	byName := map[string]Info{}
	for _, n := range names {
		byName[n.Name] = n
		if n.Size == 0 {
			t.Errorf("list %q is empty", n.Name)
		}
	}

	paths, ok := Get("paths-common")
	if !ok || len(paths) == 0 {
		t.Fatal("paths-common not found or empty")
	}
	if byName["paths-common"].Size != len(paths) {
		t.Error("Info.Size does not match Get length")
	}

	if _, ok := Get("does-not-exist"); ok {
		t.Error("unknown list should not be found")
	}
}

func TestCategoriesPresent(t *testing.T) {
	want := map[string]bool{"paths": false, "params": false, "subdomains": false, "payloads": false}
	for _, n := range Names() {
		want[n.Category] = true
	}
	for cat, present := range want {
		if !present {
			t.Errorf("missing a list in category %q", cat)
		}
	}
}
