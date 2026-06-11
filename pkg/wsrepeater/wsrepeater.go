// Package wsrepeater is a minimal WebSocket client used to compose and send
// individual frames to a target and capture the frames sent back — the
// equivalent of Burp's WebSocket Repeater. It speaks just enough of RFC 6455
// to perform the opening handshake, send one masked client frame, and read the
// server's reply frames.
package wsrepeater

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// wsGUID is the magic value from RFC 6455 §1.3 used to derive the accept key.
const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// Opcodes (RFC 6455 §5.2).
const (
	opContinuation byte = 0x0
	opText         byte = 0x1
	opBinary       byte = 0x2
	opClose        byte = 0x8
	opPing         byte = 0x9
	opPong         byte = 0xA
)

// Header is a request header for the handshake.
type Header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Options configures a single send/receive exchange.
type Options struct {
	URL           string   `json:"url"` // ws:// or wss://
	Headers       []Header  `json:"headers"`
	Opcode        string   `json:"opcode"` // "text" (default) or "binary"
	Payload       string   `json:"payload"`
	ReadTimeoutMs int      `json:"readTimeoutMs"` // how long to wait for reply frames (default 2000)
	MaxFrames     int      `json:"maxFrames"`     // stop after this many reply frames (default 16)
	Insecure      bool     `json:"insecure"`      // skip TLS verification for wss://
}

// Frame is a decoded WebSocket frame surfaced to callers.
type Frame struct {
	Opcode string `json:"opcode"` // text|binary|close|ping|pong|continuation
	Text   string `json:"text,omitempty"`
	Binary bool   `json:"binary"`
	Length int    `json:"length"`
}

// Result is the outcome of an exchange.
type Result struct {
	Sent     Frame   `json:"sent"`
	Received []Frame `json:"received"`
}

// Send performs the handshake, sends one frame, and collects reply frames until
// the read timeout elapses, a close frame arrives, or MaxFrames is reached.
func Send(ctx context.Context, opts Options) (Result, error) {
	u, err := url.Parse(strings.TrimSpace(opts.URL))
	if err != nil {
		return Result{}, fmt.Errorf("wsrepeater: invalid url: %w", err)
	}

	var useTLS bool
	switch u.Scheme {
	case "ws":
		useTLS = false
	case "wss":
		useTLS = true
	default:
		return Result{}, fmt.Errorf("wsrepeater: url scheme must be ws:// or wss:// (got %q)", u.Scheme)
	}

	readTimeout := time.Duration(opts.ReadTimeoutMs) * time.Millisecond
	if readTimeout <= 0 {
		readTimeout = 2 * time.Second
	}
	maxFrames := opts.MaxFrames
	if maxFrames <= 0 {
		maxFrames = 16
	}

	conn, err := dial(ctx, u, useTLS, opts.Insecure)
	if err != nil {
		return Result{}, err
	}
	defer conn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	br := bufio.NewReader(conn)
	if err := handshake(conn, br, u, opts.Headers); err != nil {
		return Result{}, err
	}

	opcode := opText
	if strings.EqualFold(opts.Opcode, "binary") {
		opcode = opBinary
	}

	var mask [4]byte
	if _, err := rand.Read(mask[:]); err != nil {
		return Result{}, fmt.Errorf("wsrepeater: mask: %w", err)
	}
	if _, err := conn.Write(encodeClientFrame(opcode, []byte(opts.Payload), mask)); err != nil {
		return Result{}, fmt.Errorf("wsrepeater: write frame: %w", err)
	}

	result := Result{Sent: Frame{Opcode: opcodeName(opcode), Binary: opcode == opBinary, Length: len(opts.Payload), Text: opts.Payload}}

	for len(result.Received) < maxFrames {
		_ = conn.SetReadDeadline(time.Now().Add(readTimeout))
		_, op, payload, err := decodeFrame(br)
		if err != nil {
			break // timeout / EOF / close ends collection
		}
		f := Frame{Opcode: opcodeName(op), Binary: op == opBinary, Length: len(payload)}
		if op == opText || op == opPing || op == opPong {
			f.Text = string(payload)
		}
		result.Received = append(result.Received, f)
		if op == opClose {
			break
		}
	}

	return result, nil
}

func dial(ctx context.Context, u *url.URL, useTLS, insecure bool) (net.Conn, error) {
	host := u.Host
	if u.Port() == "" {
		if useTLS {
			host = net.JoinHostPort(u.Hostname(), "443")
		} else {
			host = net.JoinHostPort(u.Hostname(), "80")
		}
	}

	d := &net.Dialer{Timeout: 10 * time.Second}
	if useTLS {
		td := &tls.Dialer{NetDialer: d, Config: &tls.Config{ServerName: u.Hostname(), InsecureSkipVerify: insecure}}
		return td.DialContext(ctx, "tcp", host)
	}
	return d.DialContext(ctx, "tcp", host)
}

func handshake(conn net.Conn, br *bufio.Reader, u *url.URL, headers []Header) error {
	var keyBytes [16]byte
	if _, err := rand.Read(keyBytes[:]); err != nil {
		return fmt.Errorf("wsrepeater: key: %w", err)
	}
	key := base64.StdEncoding.EncodeToString(keyBytes[:])

	path := u.RequestURI()
	if path == "" {
		path = "/"
	}

	var b strings.Builder
	fmt.Fprintf(&b, "GET %s HTTP/1.1\r\n", path)
	fmt.Fprintf(&b, "Host: %s\r\n", u.Host)
	b.WriteString("Upgrade: websocket\r\n")
	b.WriteString("Connection: Upgrade\r\n")
	fmt.Fprintf(&b, "Sec-WebSocket-Key: %s\r\n", key)
	b.WriteString("Sec-WebSocket-Version: 13\r\n")
	for _, h := range headers {
		if strings.EqualFold(h.Name, "host") || strings.EqualFold(h.Name, "upgrade") ||
			strings.EqualFold(h.Name, "connection") || strings.HasPrefix(strings.ToLower(h.Name), "sec-websocket") {
			continue
		}
		fmt.Fprintf(&b, "%s: %s\r\n", h.Name, h.Value)
	}
	b.WriteString("\r\n")

	if _, err := conn.Write([]byte(b.String())); err != nil {
		return fmt.Errorf("wsrepeater: write handshake: %w", err)
	}

	req := &http.Request{Method: "GET", URL: u}
	res, err := http.ReadResponse(br, req)
	if err != nil {
		return fmt.Errorf("wsrepeater: read handshake response: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusSwitchingProtocols {
		return fmt.Errorf("wsrepeater: handshake failed: server returned %s", res.Status)
	}
	if got := res.Header.Get("Sec-WebSocket-Accept"); got != computeAccept(key) {
		return fmt.Errorf("wsrepeater: invalid Sec-WebSocket-Accept")
	}
	return nil
}

// computeAccept derives the Sec-WebSocket-Accept value for a given key.
func computeAccept(key string) string {
	h := sha1.New()
	io.WriteString(h, key+wsGUID)
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// encodeClientFrame builds a single (un-fragmented) masked client frame.
func encodeClientFrame(opcode byte, payload []byte, mask [4]byte) []byte {
	var buf []byte
	buf = append(buf, 0x80|opcode) // FIN + opcode

	n := len(payload)
	switch {
	case n <= 125:
		buf = append(buf, 0x80|byte(n)) // MASK + len
	case n <= 0xFFFF:
		buf = append(buf, 0x80|126)
		var ext [2]byte
		binary.BigEndian.PutUint16(ext[:], uint16(n))
		buf = append(buf, ext[:]...)
	default:
		buf = append(buf, 0x80|127)
		var ext [8]byte
		binary.BigEndian.PutUint64(ext[:], uint64(n))
		buf = append(buf, ext[:]...)
	}

	buf = append(buf, mask[:]...)
	for i, c := range payload {
		buf = append(buf, c^mask[i%4])
	}
	return buf
}

// decodeFrame reads one frame from r, unmasking if necessary. It collapses a
// fragmented message is NOT handled here — each call returns one frame.
func decodeFrame(r *bufio.Reader) (fin bool, opcode byte, payload []byte, err error) {
	var head [2]byte
	if _, err = io.ReadFull(r, head[:]); err != nil {
		return false, 0, nil, err
	}
	fin = head[0]&0x80 != 0
	opcode = head[0] & 0x0F
	masked := head[1]&0x80 != 0
	length := int(head[1] & 0x7F)

	switch length {
	case 126:
		var ext [2]byte
		if _, err = io.ReadFull(r, ext[:]); err != nil {
			return false, 0, nil, err
		}
		length = int(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err = io.ReadFull(r, ext[:]); err != nil {
			return false, 0, nil, err
		}
		length = int(binary.BigEndian.Uint64(ext[:]))
	}

	var mask [4]byte
	if masked {
		if _, err = io.ReadFull(r, mask[:]); err != nil {
			return false, 0, nil, err
		}
	}

	payload = make([]byte, length)
	if _, err = io.ReadFull(r, payload); err != nil {
		return false, 0, nil, err
	}
	if masked {
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
	}
	return fin, opcode, payload, nil
}

func opcodeName(op byte) string {
	switch op {
	case opContinuation:
		return "continuation"
	case opText:
		return "text"
	case opBinary:
		return "binary"
	case opClose:
		return "close"
	case opPing:
		return "ping"
	case opPong:
		return "pong"
	default:
		return fmt.Sprintf("0x%x", op)
	}
}
