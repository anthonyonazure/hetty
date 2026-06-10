package proxy

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"
)

// WebSocketLogger receives WebSocket lifecycle and message events from the
// proxy. pkg/wslog implements it. All methods must be safe for concurrent use.
type WebSocketLogger interface {
	Open(url string) string
	Close(connID string)
	LogMessage(connID, url string, outgoing bool, opcode, text string, binary bool, length int)
}

// SetWebSocketLogger installs a logger that receives intercepted WebSocket
// traffic. When set, the proxy parses WS frames instead of blindly tunneling.
func (p *Proxy) SetWebSocketLogger(l WebSocketLogger) {
	p.wsLogger = l
}

// isWebSocketUpgrade reports whether r is a WebSocket upgrade request.
func isWebSocketUpgrade(r *http.Request) bool {
	return strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade") &&
		strings.EqualFold(r.Header.Get("Upgrade"), "websocket")
}

const maxWSFrame = 64 << 20 // 64 MiB payload cap

// maxWSFrame guards against absurd declared lengths.

// handleWebSocket intercepts a WebSocket upgrade: it relays the handshake to the
// target, then proxies frames in both directions while logging their payloads.
func (p *Proxy) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	useTLS := r.TLS != nil
	host := r.Host
	dialAddr := host
	if !strings.Contains(host, ":") {
		if useTLS {
			dialAddr = host + ":443"
		} else {
			dialAddr = host + ":80"
		}
	}

	scheme := "ws"
	if useTLS {
		scheme = "wss"
	}
	wsURL := fmt.Sprintf("%s://%s%s", scheme, host, r.URL.RequestURI())

	// Dial the target.
	var serverConn net.Conn
	var err error
	dialer := &net.Dialer{Timeout: 30 * time.Second}
	if useTLS {
		serverName := host
		if i := strings.IndexByte(serverName, ':'); i >= 0 {
			serverName = serverName[:i]
		}
		//nolint:gosec
		serverConn, err = tls.DialWithDialer(dialer, "tcp", dialAddr, &tls.Config{ServerName: serverName, InsecureSkipVerify: true})
	} else {
		serverConn, err = dialer.Dial("tcp", dialAddr)
	}
	if err != nil {
		p.logger.Errorw("WebSocket dial failed.", "error", err, "host", host)
		writeError(w, http.StatusBadGateway)
		return
	}
	defer serverConn.Close()

	// Forward the upgrade request to the target verbatim.
	if err := r.Write(serverConn); err != nil {
		p.logger.Errorw("WebSocket handshake forward failed.", "error", err)
		writeError(w, http.StatusBadGateway)
		return
	}

	serverReader := bufio.NewReader(serverConn)
	resp, err := http.ReadResponse(serverReader, r)
	if err != nil {
		p.logger.Errorw("WebSocket handshake response failed.", "error", err)
		writeError(w, http.StatusBadGateway)
		return
	}

	// Hijack the client connection and replay the handshake response.
	hj, ok := w.(http.Hijacker)
	if !ok {
		writeError(w, http.StatusServiceUnavailable)
		return
	}
	clientConn, clientBuf, err := hj.Hijack()
	if err != nil {
		p.logger.Errorw("WebSocket client hijack failed.", "error", err)
		return
	}
	defer clientConn.Close()

	if err := resp.Write(clientConn); err != nil {
		return
	}

	// If the upgrade didn't succeed, there's nothing more to relay.
	if resp.StatusCode != http.StatusSwitchingProtocols {
		return
	}

	var connID string
	if p.wsLogger != nil {
		connID = p.wsLogger.Open(wsURL)
		defer p.wsLogger.Close(connID)
	}

	clientReader := clientBuf.Reader

	done := make(chan struct{}, 2)
	// client -> server (outgoing, masked frames)
	go func() {
		p.relayWS(clientReader, serverConn, connID, wsURL, true)
		done <- struct{}{}
	}()
	// server -> client (incoming)
	go func() {
		p.relayWS(serverReader, clientConn, connID, wsURL, false)
		done <- struct{}{}
	}()

	// When either side closes, tear down.
	<-done
}

// relayWS reads WS frames from src, logs their payloads, and forwards the exact
// original bytes to dst until the stream ends.
func (p *Proxy) relayWS(src *bufio.Reader, dst io.Writer, connID, url string, outgoing bool) {
	for {
		f, err := readWSFrame(src)
		if err != nil {
			return
		}
		if _, err := dst.Write(f.raw); err != nil {
			return
		}
		if p.wsLogger != nil {
			p.logWSFrame(connID, url, outgoing, f)
		}
		if f.opcode == wsOpClose {
			return
		}
	}
}

func (p *Proxy) logWSFrame(connID, url string, outgoing bool, f *wsFrame) {
	switch f.opcode {
	case wsOpText:
		text := string(f.payload)
		binary := !utf8.Valid(f.payload)
		p.wsLogger.LogMessage(connID, url, outgoing, "text", text, binary, len(f.payload))
	case wsOpBinary:
		p.wsLogger.LogMessage(connID, url, outgoing, "binary", "", true, len(f.payload))
	case wsOpClose:
		p.wsLogger.LogMessage(connID, url, outgoing, "close", "", false, len(f.payload))
	case wsOpPing:
		p.wsLogger.LogMessage(connID, url, outgoing, "ping", "", false, len(f.payload))
	case wsOpPong:
		p.wsLogger.LogMessage(connID, url, outgoing, "pong", "", false, len(f.payload))
	}
}

// WebSocket opcodes (RFC 6455 §5.2).
const (
	wsOpContinuation byte = 0x0
	wsOpText         byte = 0x1
	wsOpBinary       byte = 0x2
	wsOpClose        byte = 0x8
	wsOpPing         byte = 0x9
	wsOpPong         byte = 0xA
)

type wsFrame struct {
	fin     bool
	opcode  byte
	masked  bool
	payload []byte // unmasked decoded payload
	raw     []byte // exact original bytes, for verbatim forwarding
}

// readWSFrame parses a single WebSocket frame, returning both the decoded
// payload and the original wire bytes.
func readWSFrame(r *bufio.Reader) (*wsFrame, error) {
	raw := make([]byte, 0, 14)

	b0, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	b1, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	raw = append(raw, b0, b1)

	f := &wsFrame{
		fin:    b0&0x80 != 0,
		opcode: b0 & 0x0F,
		masked: b1&0x80 != 0,
	}
	length := int(b1 & 0x7F)

	switch length {
	case 126:
		ext := make([]byte, 2)
		if _, err := io.ReadFull(r, ext); err != nil {
			return nil, err
		}
		raw = append(raw, ext...)
		length = int(binary.BigEndian.Uint16(ext))
	case 127:
		ext := make([]byte, 8)
		if _, err := io.ReadFull(r, ext); err != nil {
			return nil, err
		}
		raw = append(raw, ext...)
		length = int(binary.BigEndian.Uint64(ext))
	}

	if length < 0 || length > maxWSFrame {
		return nil, fmt.Errorf("proxy: websocket frame length %d out of range", length)
	}

	var maskKey []byte
	if f.masked {
		maskKey = make([]byte, 4)
		if _, err := io.ReadFull(r, maskKey); err != nil {
			return nil, err
		}
		raw = append(raw, maskKey...)
	}

	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	raw = append(raw, payload...)

	if f.masked {
		decoded := make([]byte, length)
		for i := 0; i < length; i++ {
			decoded[i] = payload[i] ^ maskKey[i%4]
		}
		f.payload = decoded
	} else {
		f.payload = payload
	}

	f.raw = raw
	return f, nil
}
