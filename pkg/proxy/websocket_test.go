package proxy

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"net/http"
	"testing"
)

// buildFrame constructs a WebSocket frame on the wire.
func buildFrame(opcode byte, payload []byte, maskKey []byte) []byte {
	var b []byte
	b = append(b, 0x80|opcode) // FIN + opcode

	masked := maskKey != nil
	var lenByte byte
	if masked {
		lenByte = 0x80
	}

	n := len(payload)
	switch {
	case n < 126:
		b = append(b, lenByte|byte(n))
	case n < 65536:
		b = append(b, lenByte|126)
		ext := make([]byte, 2)
		binary.BigEndian.PutUint16(ext, uint16(n))
		b = append(b, ext...)
	default:
		b = append(b, lenByte|127)
		ext := make([]byte, 8)
		binary.BigEndian.PutUint64(ext, uint64(n))
		b = append(b, ext...)
	}

	if masked {
		b = append(b, maskKey...)
		for i := 0; i < n; i++ {
			b = append(b, payload[i]^maskKey[i%4])
		}
	} else {
		b = append(b, payload...)
	}
	return b
}

func TestReadWSFrameUnmasked(t *testing.T) {
	wire := buildFrame(wsOpText, []byte("hello"), nil)
	f, err := readWSFrame(bufio.NewReader(bytes.NewReader(wire)))
	if err != nil {
		t.Fatal(err)
	}
	if f.opcode != wsOpText {
		t.Errorf("opcode = %d, want text", f.opcode)
	}
	if string(f.payload) != "hello" {
		t.Errorf("payload = %q, want hello", f.payload)
	}
	if !bytes.Equal(f.raw, wire) {
		t.Error("raw bytes must equal the original wire bytes for verbatim forwarding")
	}
	if f.masked {
		t.Error("frame should not be masked")
	}
}

func TestReadWSFrameMaskedDecodes(t *testing.T) {
	maskKey := []byte{0xA1, 0xB2, 0xC3, 0xD4}
	wire := buildFrame(wsOpText, []byte("secret payload"), maskKey)
	f, err := readWSFrame(bufio.NewReader(bytes.NewReader(wire)))
	if err != nil {
		t.Fatal(err)
	}
	if !f.masked {
		t.Error("frame should be detected as masked")
	}
	if string(f.payload) != "secret payload" {
		t.Errorf("decoded payload = %q, want 'secret payload'", f.payload)
	}
	// The forwarded bytes must remain the original masked bytes.
	if !bytes.Equal(f.raw, wire) {
		t.Error("raw bytes must be preserved unmasked-on-the-wire")
	}
}

func TestReadWSFrameExtendedLength(t *testing.T) {
	payload := bytes.Repeat([]byte("A"), 300) // forces 16-bit extended length
	wire := buildFrame(wsOpBinary, payload, nil)
	f, err := readWSFrame(bufio.NewReader(bytes.NewReader(wire)))
	if err != nil {
		t.Fatal(err)
	}
	if len(f.payload) != 300 {
		t.Errorf("payload len = %d, want 300", len(f.payload))
	}
	if f.opcode != wsOpBinary {
		t.Errorf("opcode = %d, want binary", f.opcode)
	}
}

func TestReadMultipleFrames(t *testing.T) {
	var buf bytes.Buffer
	buf.Write(buildFrame(wsOpText, []byte("one"), nil))
	buf.Write(buildFrame(wsOpText, []byte("two"), []byte{1, 2, 3, 4}))
	r := bufio.NewReader(&buf)

	f1, err := readWSFrame(r)
	if err != nil || string(f1.payload) != "one" {
		t.Fatalf("frame 1: %v / %q", err, f1.payload)
	}
	f2, err := readWSFrame(r)
	if err != nil || string(f2.payload) != "two" {
		t.Fatalf("frame 2: %v / %q", err, f2.payload)
	}
}

func TestIsWebSocketUpgrade(t *testing.T) {
	r, _ := http.NewRequest("GET", "http://x/ws", nil)
	r.Header.Set("Connection", "Upgrade")
	r.Header.Set("Upgrade", "websocket")
	if !isWebSocketUpgrade(r) {
		t.Error("should detect websocket upgrade")
	}

	r2, _ := http.NewRequest("GET", "http://x/", nil)
	if isWebSocketUpgrade(r2) {
		t.Error("plain request is not an upgrade")
	}
}
