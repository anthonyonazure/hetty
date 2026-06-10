package bolt

import (
	"path/filepath"
	"testing"
)

func TestSaveLoadState(t *testing.T) {
	db, err := OpenDatabase(filepath.Join(t.TempDir(), "state.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// Missing key returns nil, no error.
	d, err := db.LoadState("missing")
	if err != nil {
		t.Fatal(err)
	}
	if d != nil {
		t.Errorf("missing key = %q, want nil", d)
	}

	// Save then load.
	if err := db.SaveState("sitemap", []byte("hello")); err != nil {
		t.Fatal(err)
	}
	d, _ = db.LoadState("sitemap")
	if string(d) != "hello" {
		t.Errorf("loaded %q, want hello", d)
	}

	// Overwrite.
	if err := db.SaveState("sitemap", []byte("world")); err != nil {
		t.Fatal(err)
	}
	d, _ = db.LoadState("sitemap")
	if string(d) != "world" {
		t.Errorf("loaded %q, want world", d)
	}
}
