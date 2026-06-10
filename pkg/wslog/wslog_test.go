package wslog

import "testing"

func TestOpenLogClose(t *testing.T) {
	s := New()
	id := s.Open("wss://ex.com/socket")
	if id == "" {
		t.Fatal("expected a connection id")
	}

	s.LogMessage(id, "wss://ex.com/socket", true, "text", `{"action":"subscribe"}`, false, 22)
	s.LogMessage(id, "wss://ex.com/socket", false, "text", `{"ok":true}`, false, 11)

	msgs := s.Messages(id)
	if len(msgs) != 2 {
		t.Fatalf("messages = %d, want 2", len(msgs))
	}
	if msgs[0].Direction != Outgoing {
		t.Errorf("first message direction = %q, want outgoing", msgs[0].Direction)
	}
	if msgs[1].Direction != Incoming {
		t.Errorf("second message direction = %q, want incoming", msgs[1].Direction)
	}

	conns := s.Connections()
	if len(conns) != 1 || conns[0].Messages != 2 {
		t.Errorf("connection summary wrong: %+v", conns)
	}

	s.Close(id)
	if !s.Connections()[0].Closed {
		t.Error("connection should be marked closed")
	}
}

func TestMessagesFilter(t *testing.T) {
	s := New()
	a := s.Open("wss://a")
	b := s.Open("wss://b")
	s.LogMessage(a, "wss://a", true, "text", "x", false, 1)
	s.LogMessage(b, "wss://b", true, "text", "y", false, 1)

	if len(s.Messages(a)) != 1 {
		t.Error("filter by conn a should yield 1")
	}
	if len(s.Messages("")) != 2 {
		t.Error("no filter should yield all")
	}
}

func TestClear(t *testing.T) {
	s := New()
	id := s.Open("wss://x")
	s.LogMessage(id, "wss://x", true, "text", "x", false, 1)
	s.Clear()
	if len(s.Connections()) != 0 || len(s.Messages("")) != 0 {
		t.Error("store should be empty after clear")
	}
}
