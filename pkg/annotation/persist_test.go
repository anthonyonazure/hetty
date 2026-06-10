package annotation

import "testing"

func TestSnapshotRestoreRoundTrip(t *testing.T) {
	s := New()
	if _, err := s.Set(Annotation{TargetID: "req-1", Color: "red", Note: "idor candidate"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Set(Annotation{TargetID: "req-2", Note: "review"}); err != nil {
		t.Fatal(err)
	}

	data, err := s.Snapshot()
	if err != nil {
		t.Fatal(err)
	}

	restored := New()
	if err := restored.Restore(data); err != nil {
		t.Fatal(err)
	}

	a, ok := restored.Get("req-1")
	if !ok || a.Color != "red" || a.Note != "idor candidate" {
		t.Errorf("annotation not restored: %+v (ok=%v)", a, ok)
	}
	if a.UpdatedAt.IsZero() {
		t.Error("UpdatedAt should be preserved across restore")
	}
	if len(restored.All()) != 2 {
		t.Errorf("All() = %d after restore, want 2", len(restored.All()))
	}
}
