package collab

import (
	"net/http/httptest"
	"testing"
)

func TestSnapshotRestoreRoundTrip(t *testing.T) {
	s := NewServer("http://localhost/oob")
	token, _ := s.NewToken()

	// Simulate a recorded callback.
	req := httptest.NewRequest("GET", "/"+token+"?x=1", nil)
	s.record(token, req)

	if s.InteractionCount(token) != 1 {
		t.Fatalf("setup: interaction count = %d, want 1", s.InteractionCount(token))
	}

	data, err := s.Snapshot()
	if err != nil {
		t.Fatal(err)
	}

	restored := NewServer("http://localhost/oob")
	if err := restored.Restore(data); err != nil {
		t.Fatal(err)
	}

	if restored.InteractionCount(token) != 1 {
		t.Errorf("interaction count after restore = %d, want 1", restored.InteractionCount(token))
	}
	inter := restored.Interactions(token)
	if len(inter) != 1 || inter[0].Token != token {
		t.Errorf("interaction not restored: %+v", inter)
	}
}
