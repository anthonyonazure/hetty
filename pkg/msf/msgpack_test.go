package msf

import (
	"reflect"
	"testing"
)

func TestMsgpackRoundTrip(t *testing.T) {
	value := []interface{}{
		"auth.login",
		"user",
		map[string]interface{}{
			"RHOSTS": "10.0.0.1",
			"RPORT":  int64(21),
			"flag":   true,
			"none":   nil,
		},
		int64(-5),
		int64(300),
		[]interface{}{"a", "b"},
	}

	encoded := mpEncode(value)
	decoded, err := mpDecode(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !reflect.DeepEqual(decoded, value) {
		t.Fatalf("round trip mismatch:\n got %#v\nwant %#v", decoded, value)
	}
}

// Decode a hand-crafted fixmap {"version": "6.3.0"} to validate the decoder
// independently of the encoder.
func TestMsgpackDecodeHandCrafted(t *testing.T) {
	data := []byte{
		0x81,                               // fixmap, 1 entry
		0xa7, 'v', 'e', 'r', 's', 'i', 'o', 'n', // fixstr "version"
		0xa5, '6', '.', '3', '.', '0', // fixstr "6.3.0"
	}
	v, err := mpDecode(data)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	m, ok := v.(map[string]interface{})
	if !ok || m["version"] != "6.3.0" {
		t.Fatalf("got %#v", v)
	}
}

func TestMsgpackBinDecodesToString(t *testing.T) {
	// bin8 "tok" -> should decode to the Go string "tok".
	data := []byte{0xc4, 0x03, 't', 'o', 'k'}
	v, err := mpDecode(data)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if v != "tok" {
		t.Fatalf("bin should decode to string, got %#v", v)
	}
}

func TestMsgpackLargeString(t *testing.T) {
	big := make([]byte, 500)
	for i := range big {
		big[i] = 'x'
	}
	encoded := mpEncode(string(big))
	decoded, err := mpDecode(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded != string(big) {
		t.Fatalf("large string round trip failed")
	}
}
