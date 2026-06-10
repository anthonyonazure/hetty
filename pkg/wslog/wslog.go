// Package wslog stores WebSocket messages observed by the proxy so they can be
// inspected in the admin UI — the equivalent of Burp's "WebSockets history".
// Messages are held in memory, grouped by connection.
package wslog

import (
	"encoding/json"
	"sort"
	"sync"
	"time"
)

// Direction is the travel direction of a message.
type Direction string

const (
	Outgoing Direction = "outgoing" // client -> server
	Incoming Direction = "incoming" // server -> client
)

// Message is one observed WebSocket frame's payload.
type Message struct {
	ID        string    `json:"id"`
	ConnID    string    `json:"connId"`
	URL       string    `json:"url"`
	Direction Direction `json:"direction"`
	Opcode    string    `json:"opcode"`
	Text      string    `json:"text,omitempty"`
	Binary    bool      `json:"binary"`
	Length    int       `json:"length"`
	Time      time.Time `json:"time"`
}

// Connection summarizes one WebSocket connection.
type Connection struct {
	ID       string    `json:"id"`
	URL      string    `json:"url"`
	OpenedAt time.Time `json:"openedAt"`
	Closed   bool      `json:"closed"`
	Messages int       `json:"messages"`
}

// Store holds observed messages and connections.
type Store struct {
	mu       sync.Mutex
	now      func() time.Time
	seq      uint64
	conns    map[string]*Connection
	messages []Message
}

// New returns an empty store.
func New() *Store {
	return &Store{
		now:   time.Now,
		conns: make(map[string]*Connection),
	}
}

func (s *Store) nextID() string {
	s.seq++
	const hexdigits = "0123456789abcdef"
	v := s.seq
	var out [8]byte
	for i := 0; i < 8; i++ {
		out[7-i] = hexdigits[v&0xF]
		v >>= 4
	}
	return string(out[:])
}

// Open records a new WebSocket connection and returns its ID.
func (s *Store) Open(url string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := s.nextID()
	s.conns[id] = &Connection{ID: id, URL: url, OpenedAt: s.now().UTC()}
	return id
}

// Close marks a connection closed.
func (s *Store) Close(connID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c, ok := s.conns[connID]; ok {
		c.Closed = true
	}
}

// LogMessage records a message frame. It matches the proxy.WebSocketLogger
// signature so the store can be installed directly. text holds the decoded
// payload (UTF-8 for text frames); binary marks non-text payloads.
func (s *Store) LogMessage(connID, url string, outgoing bool, opcode, text string, binary bool, length int) {
	dir := Incoming
	if outgoing {
		dir = Outgoing
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.messages = append(s.messages, Message{
		ID:        s.nextID(),
		ConnID:    connID,
		URL:       url,
		Direction: dir,
		Opcode:    opcode,
		Text:      text,
		Binary:    binary,
		Length:    length,
		Time:      s.now().UTC(),
	})
	if c, ok := s.conns[connID]; ok {
		c.Messages++
	}
}

// Messages returns all messages, optionally filtered by connection ID.
func (s *Store) Messages(connID string) []Message {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Message, 0, len(s.messages))
	for _, m := range s.messages {
		if connID == "" || m.ConnID == connID {
			out = append(out, m)
		}
	}
	return out
}

// Connections returns all connections, newest first.
func (s *Store) Connections() []Connection {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Connection, 0, len(s.conns))
	for _, c := range s.conns {
		out = append(out, *c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].OpenedAt.After(out[j].OpenedAt) })
	return out
}

// Clear empties the store.
func (s *Store) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.conns = make(map[string]*Connection)
	s.messages = nil
}

type wsSnapshot struct {
	Seq      uint64                 `json:"seq"`
	Conns    map[string]*Connection `json:"conns"`
	Messages []Message              `json:"messages"`
}

// Snapshot serializes the store for persistence.
func (s *Store) Snapshot() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return json.Marshal(wsSnapshot{Seq: s.seq, Conns: s.conns, Messages: s.messages})
}

// Restore loads connections and messages from a snapshot.
func (s *Store) Restore(data []byte) error {
	if len(data) == 0 {
		return nil
	}
	var snap wsSnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if snap.Conns != nil {
		s.conns = snap.Conns
	}
	s.messages = snap.Messages
	s.seq = snap.Seq
	return nil
}
