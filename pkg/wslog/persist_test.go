package wslog

import "testing"

func TestSnapshotRestoreRoundTrip(t *testing.T) {
	s := New()
	id := s.Open("wss://ex.com/socket")
	s.LogMessage(id, "wss://ex.com/socket", true, "text", "hello", false, 5)
	s.LogMessage(id, "wss://ex.com/socket", false, "text", "world", false, 5)

	data, err := s.Snapshot()
	if err != nil {
		t.Fatal(err)
	}

	restored := New()
	if err := restored.Restore(data); err != nil {
		t.Fatal(err)
	}

	if len(restored.Messages("")) != 2 {
		t.Errorf("messages after restore = %d, want 2", len(restored.Messages("")))
	}
	conns := restored.Connections()
	if len(conns) != 1 || conns[0].Messages != 2 {
		t.Errorf("connections not restored: %+v", conns)
	}

	// New messages on the restored store must keep unique IDs (seq restored).
	newID := restored.Open("wss://ex.com/other")
	if newID == id {
		t.Error("restored store reissued an existing connection id — seq not restored")
	}
}
