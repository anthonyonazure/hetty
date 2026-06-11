package wsrepeater

import (
	"bufio"
	"bytes"
	"context"
	"testing"
	"time"
)

// RFC 6455 §1.3 worked example.
func TestComputeAccept(t *testing.T) {
	if got := computeAccept("dGhlIHNhbXBsZSBub25jZQ=="); got != "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" {
		t.Fatalf("computeAccept = %q, want s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", got)
	}
}

func TestFrameRoundTrip(t *testing.T) {
	mask := [4]byte{0xDE, 0xAD, 0xBE, 0xEF}
	cases := []struct {
		op      byte
		payload string
	}{
		{opText, "hello hetty"},
		{opBinary, string(bytes.Repeat([]byte{0x00, 0x01, 0x02}, 50))}, // 150 bytes -> 16-bit length
		{opText, ""},
		{opText, string(bytes.Repeat([]byte("A"), 70000))}, // 64-bit length path
	}
	for i, c := range cases {
		encoded := encodeClientFrame(c.op, []byte(c.payload), mask)
		// Client frames must set the MASK bit.
		if encoded[1]&0x80 == 0 {
			t.Fatalf("case %d: client frame not masked", i)
		}
		fin, op, payload, err := decodeFrame(bufio.NewReader(bytes.NewReader(encoded)))
		if err != nil {
			t.Fatalf("case %d: decode: %v", i, err)
		}
		if !fin {
			t.Errorf("case %d: expected FIN", i)
		}
		if op != c.op {
			t.Errorf("case %d: opcode = %x, want %x", i, op, c.op)
		}
		if string(payload) != c.payload {
			t.Errorf("case %d: payload mismatch (len got %d want %d)", i, len(payload), len(c.payload))
		}
	}
}

func TestDecodeServerFrameUnmasked(t *testing.T) {
	// Server frames are NOT masked: FIN+text, len 3, "abc".
	raw := []byte{0x81, 0x03, 'a', 'b', 'c'}
	_, op, payload, err := decodeFrame(bufio.NewReader(bytes.NewReader(raw)))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if op != opText || string(payload) != "abc" {
		t.Fatalf("got op=%x payload=%q", op, payload)
	}
}

func TestSendRejectsBadScheme(t *testing.T) {
	_, err := Send(context.Background(), Options{URL: "http://example.com/"})
	if err == nil {
		t.Fatal("expected error for non-ws scheme")
	}
}

func TestOpcodeName(t *testing.T) {
	if opcodeName(opClose) != "close" || opcodeName(opPong) != "pong" {
		t.Fatal("opcode names wrong")
	}
}

// Guard: encoding a 200-byte payload must use the 126 extended-length form.
func TestExtendedLength16(t *testing.T) {
	mask := [4]byte{1, 2, 3, 4}
	encoded := encodeClientFrame(opText, bytes.Repeat([]byte("x"), 200), mask)
	if encoded[1]&0x7F != 126 {
		t.Fatalf("expected 126 length marker, got %d", encoded[1]&0x7F)
	}
	_ = time.Now
}
