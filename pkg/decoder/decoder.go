// Package decoder implements Hetty's Decoder tool: a registry of reversible
// codecs (URL, Base64, hex, HTML, gzip, zlib) and one-way hashes (MD5, SHA),
// plus a JWT decoder and a smart-decode heuristic that recursively unwraps a
// value through likely encodings.
package decoder

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/url"
	"sort"
	"strings"
	"unicode/utf8"
)

// Op is an encode or decode operation.
type Op string

const (
	OpEncode Op = "encode"
	OpDecode Op = "decode"
)

// Codec is a named, optionally-reversible transform.
type Codec struct {
	ID        string
	Name      string
	CanEncode bool
	CanDecode bool

	encode func([]byte) ([]byte, error)
	decode func([]byte) ([]byte, error)
}

var registry = buildRegistry()

func buildRegistry() map[string]Codec {
	codecs := []Codec{
		{
			ID: "url", Name: "URL", CanEncode: true, CanDecode: true,
			encode: func(b []byte) ([]byte, error) { return []byte(url.QueryEscape(string(b))), nil },
			decode: func(b []byte) ([]byte, error) {
				s, err := url.QueryUnescape(string(b))
				return []byte(s), err
			},
		},
		{
			ID: "base64", Name: "Base64", CanEncode: true, CanDecode: true,
			encode: func(b []byte) ([]byte, error) {
				return []byte(base64.StdEncoding.EncodeToString(b)), nil
			},
			decode: func(b []byte) ([]byte, error) {
				return base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
			},
		},
		{
			ID: "base64url", Name: "Base64 URL-safe", CanEncode: true, CanDecode: true,
			encode: func(b []byte) ([]byte, error) {
				return []byte(base64.RawURLEncoding.EncodeToString(b)), nil
			},
			decode: func(b []byte) ([]byte, error) {
				return base64.RawURLEncoding.DecodeString(strings.TrimRight(strings.TrimSpace(string(b)), "="))
			},
		},
		{
			ID: "hex", Name: "Hex (ASCII)", CanEncode: true, CanDecode: true,
			encode: func(b []byte) ([]byte, error) { return []byte(hex.EncodeToString(b)), nil },
			decode: func(b []byte) ([]byte, error) {
				return hex.DecodeString(strings.TrimSpace(string(b)))
			},
		},
		{
			ID: "html", Name: "HTML entities", CanEncode: true, CanDecode: true,
			encode: func(b []byte) ([]byte, error) { return []byte(html.EscapeString(string(b))), nil },
			decode: func(b []byte) ([]byte, error) { return []byte(html.UnescapeString(string(b))), nil },
		},
		{
			ID: "gzip", Name: "Gzip", CanEncode: true, CanDecode: true,
			encode: func(b []byte) ([]byte, error) {
				var buf bytes.Buffer
				w := gzip.NewWriter(&buf)
				if _, err := w.Write(b); err != nil {
					return nil, err
				}
				if err := w.Close(); err != nil {
					return nil, err
				}
				return buf.Bytes(), nil
			},
			decode: func(b []byte) ([]byte, error) {
				r, err := gzip.NewReader(bytes.NewReader(b))
				if err != nil {
					return nil, err
				}
				defer r.Close()
				return io.ReadAll(r)
			},
		},
		{
			ID: "zlib", Name: "Zlib (deflate)", CanEncode: true, CanDecode: true,
			encode: func(b []byte) ([]byte, error) {
				var buf bytes.Buffer
				w := zlib.NewWriter(&buf)
				if _, err := w.Write(b); err != nil {
					return nil, err
				}
				if err := w.Close(); err != nil {
					return nil, err
				}
				return buf.Bytes(), nil
			},
			decode: func(b []byte) ([]byte, error) {
				r, err := zlib.NewReader(bytes.NewReader(b))
				if err != nil {
					return nil, err
				}
				defer r.Close()
				return io.ReadAll(r)
			},
		},
		{
			ID: "jwt", Name: "JWT (decode)", CanEncode: false, CanDecode: true,
			decode: decodeJWT,
		},
		hashCodec("md5", "MD5", func(b []byte) []byte { s := md5.Sum(b); return s[:] }),
		hashCodec("sha1", "SHA-1", func(b []byte) []byte { s := sha1.Sum(b); return s[:] }),
		hashCodec("sha256", "SHA-256", func(b []byte) []byte { s := sha256.Sum256(b); return s[:] }),
		hashCodec("sha512", "SHA-512", func(b []byte) []byte { s := sha512.Sum512(b); return s[:] }),
	}

	m := make(map[string]Codec, len(codecs))
	for _, c := range codecs {
		m[c.ID] = c
	}

	return m
}

func hashCodec(id, name string, sum func([]byte) []byte) Codec {
	return Codec{
		ID: id, Name: name, CanEncode: true, CanDecode: false,
		encode: func(b []byte) ([]byte, error) { return []byte(hex.EncodeToString(sum(b))), nil },
	}
}

func decodeJWT(b []byte) ([]byte, error) {
	parts := strings.Split(strings.TrimSpace(string(b)), ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("decoder: not a JWT (expected at least 2 dot-separated parts)")
	}

	decodePart := func(p string) (json.RawMessage, error) {
		raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(p, "="))
		if err != nil {
			return nil, err
		}
		return json.RawMessage(raw), nil
	}

	header, err := decodePart(parts[0])
	if err != nil {
		return nil, fmt.Errorf("decoder: invalid JWT header: %w", err)
	}

	payload, err := decodePart(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decoder: invalid JWT payload: %w", err)
	}

	out := struct {
		Header    json.RawMessage `json:"header"`
		Payload   json.RawMessage `json:"payload"`
		Signature string          `json:"signature"`
	}{Header: header, Payload: payload}
	if len(parts) > 2 {
		out.Signature = parts[2]
	}

	pretty, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return nil, err
	}

	return pretty, nil
}

// Codecs returns the registered codecs sorted by ID.
func Codecs() []Codec {
	out := make([]Codec, 0, len(registry))
	for _, c := range registry {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })

	return out
}

// Apply runs a single codec operation.
func Apply(id string, op Op, input []byte) ([]byte, error) {
	c, ok := registry[id]
	if !ok {
		return nil, fmt.Errorf("decoder: unknown codec %q", id)
	}

	switch op {
	case OpEncode:
		if !c.CanEncode || c.encode == nil {
			return nil, fmt.Errorf("decoder: codec %q does not support encode", id)
		}
		return c.encode(input)
	case OpDecode:
		if !c.CanDecode || c.decode == nil {
			return nil, fmt.Errorf("decoder: codec %q does not support decode", id)
		}
		return c.decode(input)
	default:
		return nil, fmt.Errorf("decoder: unknown operation %q", op)
	}
}

// Step is one stage of a smart-decode chain.
type Step struct {
	Codec  string `json:"codec"`
	Output string `json:"output"`
}

// SmartDecode recursively decodes input through the codecs most likely to
// apply, stopping when no further decoding makes progress or the depth limit
// is reached. It returns the chain of successful decodes.
func SmartDecode(input []byte) []Step {
	const maxDepth = 8

	var steps []Step
	current := input

	for depth := 0; depth < maxDepth; depth++ {
		codecID, decoded, ok := bestDecode(current)
		if !ok {
			break
		}

		steps = append(steps, Step{Codec: codecID, Output: string(decoded)})
		current = decoded
	}

	return steps
}

// bestDecode tries candidate codecs in priority order and returns the first
// that yields a "better" result (still valid text, and meaningfully changed).
func bestDecode(input []byte) (string, []byte, bool) {
	s := strings.TrimSpace(string(input))
	if s == "" {
		return "", nil, false
	}

	for _, id := range []string{"url", "jwt", "base64url", "base64", "hex", "gzip", "zlib"} {
		c := registry[id]
		if !c.CanDecode {
			continue
		}

		out, err := c.decode([]byte(s))
		if err != nil || len(out) == 0 {
			continue
		}

		if string(out) == s {
			continue // no progress
		}

		// Require the decode to look like reasonable text, except for
		// compression codecs which we trust if they succeeded.
		if id == "gzip" || id == "zlib" || id == "jwt" {
			return id, out, true
		}

		if looksDecodable(s, out, id) {
			return id, out, true
		}
	}

	return "", nil, false
}

// looksDecodable applies per-codec sanity checks to avoid bogus decodes (e.g.
// decoding ordinary text as base64).
func looksDecodable(input string, output []byte, codecID string) bool {
	if !utf8.Valid(output) {
		return false
	}

	switch codecID {
	case "url":
		return strings.ContainsAny(input, "%+")
	case "base64", "base64url":
		// Heuristic: base64 alphabet only, length sane, decoded text mostly
		// printable.
		if len(input) < 8 || len(input)%4 != 0 && codecID == "base64" {
			return false
		}
		return isMostlyPrintable(output)
	case "hex":
		return len(input) >= 8 && len(input)%2 == 0 && isMostlyPrintable(output)
	default:
		return isMostlyPrintable(output)
	}
}

func isMostlyPrintable(b []byte) bool {
	if len(b) == 0 {
		return false
	}

	printable := 0
	for _, r := range string(b) {
		if r == '\n' || r == '\r' || r == '\t' || (r >= 0x20 && r != utf8.RuneError) {
			printable++
		}
	}

	return float64(printable)/float64(utf8.RuneCountInString(string(b))) > 0.85
}
