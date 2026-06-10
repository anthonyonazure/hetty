package decoder_test

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/dstotijn/hetty/pkg/decoder"
)

func TestRoundTrips(t *testing.T) {
	input := []byte("Hello, Hetty! <world> & 100%")

	for _, id := range []string{"url", "base64", "base64url", "hex", "html", "gzip", "zlib"} {
		t.Run(id, func(t *testing.T) {
			enc, err := decoder.Apply(id, decoder.OpEncode, input)
			if err != nil {
				t.Fatalf("encode: %v", err)
			}

			dec, err := decoder.Apply(id, decoder.OpDecode, enc)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}

			if string(dec) != string(input) {
				t.Errorf("round trip mismatch: got %q, want %q", dec, input)
			}
		})
	}
}

func TestHashes(t *testing.T) {
	input := []byte("abc")
	cases := map[string]string{
		"md5":    "900150983cd24fb0d6963f7d28e17f72",
		"sha1":   "a9993e364706816aba3e25717850c26c9cd0d89d",
		"sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
	}

	for id, want := range cases {
		out, err := decoder.Apply(id, decoder.OpEncode, input)
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		if string(out) != want {
			t.Errorf("%s(abc) = %s, want %s", id, out, want)
		}
	}

	if _, err := decoder.Apply("sha256", decoder.OpDecode, input); err == nil {
		t.Error("expected error decoding with a hash codec")
	}
}

func TestJWTDecode(t *testing.T) {
	// Build a token at runtime to avoid embedding an opaque literal.
	enc := base64.RawURLEncoding.EncodeToString
	header := enc([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload := enc([]byte(`{"sub":"123","name":"Hetty"}`))
	token := header + "." + payload + ".signaturepart"

	out, err := decoder.Apply("jwt", decoder.OpDecode, []byte(token))
	if err != nil {
		t.Fatalf("jwt decode: %v", err)
	}

	s := string(out)
	if !strings.Contains(s, "HS256") || !strings.Contains(s, "Hetty") {
		t.Errorf("jwt decode missing expected fields: %s", s)
	}
}

func TestSmartDecode(t *testing.T) {
	// base64("Hello Hetty") = SGVsbG8gSGV0dHk=
	encoded := base64.StdEncoding.EncodeToString([]byte("Hello Hetty"))

	steps := decoder.SmartDecode([]byte(encoded))
	if len(steps) == 0 {
		t.Fatal("expected at least one smart-decode step")
	}

	last := steps[len(steps)-1]
	if !strings.Contains(last.Output, "Hello Hetty") {
		t.Errorf("smart decode final output = %q, want to contain 'Hello Hetty'", last.Output)
	}
}
