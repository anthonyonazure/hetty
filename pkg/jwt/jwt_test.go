package jwt

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	// Build a real token so the signature is valid rather than fabricated.
	raw, err := SignHS(`{"alg":"HS256","typ":"JWT"}`, `{"sub":"123","admin":false}`, "secret", "HS256")
	if err != nil {
		t.Fatal(err)
	}
	tok, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if tok.Alg != "HS256" {
		t.Errorf("alg = %q, want HS256", tok.Alg)
	}
	if tok.Payload["sub"] != "123" {
		t.Errorf("sub = %v, want 123", tok.Payload["sub"])
	}
	if tok.Payload["admin"] != false {
		t.Errorf("admin = %v, want false", tok.Payload["admin"])
	}
}

func TestSignAndVerifyRoundTrip(t *testing.T) {
	raw, err := SignHS(`{"alg":"HS256","typ":"JWT"}`, `{"sub":"123","admin":true}`, "secret", "HS256")
	if err != nil {
		t.Fatal(err)
	}
	ok, err := VerifyHS(raw, "secret")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Error("token should verify with correct secret")
	}
	ok, _ = VerifyHS(raw, "wrong")
	if ok {
		t.Error("token should not verify with wrong secret")
	}

	tok, _ := Parse(raw)
	if tok.Payload["admin"] != true {
		t.Errorf("admin = %v, want true", tok.Payload["admin"])
	}
}

func TestAlgNone(t *testing.T) {
	raw, err := AlgNone(`{"alg":"HS256","typ":"JWT"}`, `{"sub":"123","admin":true}`, "none")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(raw, ".") {
		t.Error("alg:none token must have an empty signature segment")
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		t.Fatalf("alg:none token should have 3 segments, got %d", len(parts))
	}
}

func TestAlgNoneVariant(t *testing.T) {
	raw, _ := AlgNone(`{"alg":"HS256"}`, `{"x":1}`, "NONE")
	hdr, _ := b64dec(strings.Split(raw, ".")[0])
	var h map[string]interface{}
	_ = json.Unmarshal(hdr, &h)
	if h["alg"] != "NONE" {
		t.Errorf("alg variant = %v, want NONE", h["alg"])
	}
}

func TestBruteHS(t *testing.T) {
	raw, _ := SignHS(`{"alg":"HS256","typ":"JWT"}`, `{"sub":"1"}`, "changeme", "HS256")
	res, err := BruteHS(raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Found || res.Secret != "changeme" {
		t.Errorf("brute = %+v, want found changeme", res)
	}
}

func TestBruteHSNotFound(t *testing.T) {
	raw, _ := SignHS(`{"alg":"HS256"}`, `{"x":1}`, "a-very-unlikely-secret-xyz", "HS256")
	res, _ := BruteHS(raw, []string{"a", "b", "c"})
	if res.Found {
		t.Error("should not find secret")
	}
	if res.Tried != 3 {
		t.Errorf("tried = %d, want 3", res.Tried)
	}
}