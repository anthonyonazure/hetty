package smuggle

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

// rawMock is a TCP server that simulates a back-end which hangs (delays its
// response) when it receives a request matching delayMatch — standing in for a
// smuggling-vulnerable server that blocks waiting for body bytes.
func rawMock(t *testing.T, delay time.Duration, delayMatch func(string) bool) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
				buf := make([]byte, 8192)
				n, _ := c.Read(buf)
				raw := string(buf[:n])
				if delayMatch(raw) {
					time.Sleep(delay)
				}
				_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"))
			}(conn)
		}
	}()

	return ln.Addr().String(), func() { ln.Close() }
}

func TestProbeDetectsCLTE(t *testing.T) {
	// Delay only on the CL.TE-specific body, so TE.CL stays fast.
	addr, closeFn := rawMock(t, 600*time.Millisecond, func(raw string) bool {
		return strings.Contains(raw, "1\r\nA\r\nX")
	})
	defer closeFn()

	res, err := Probe(context.Background(), "http://"+addr+"/", Options{
		DelayThresholdMs: 200,
		ReadTimeoutMs:    2000,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Vulnerable {
		t.Fatalf("expected vulnerable; findings=%+v", res.Findings)
	}

	var clte, tecl *Finding
	for i := range res.Findings {
		switch res.Findings[i].Technique {
		case CLTE:
			clte = &res.Findings[i]
		case TECL:
			tecl = &res.Findings[i]
		}
	}
	if clte == nil || !strings.Contains(clte.Detail, "desync") {
		t.Errorf("CL.TE not flagged: %+v", clte)
	}
	if tecl == nil || tecl.Detail != "no significant delay" {
		t.Errorf("TE.CL should be clean: %+v", tecl)
	}
}

func TestProbeCleanServer(t *testing.T) {
	// Never delays — a non-vulnerable server.
	addr, closeFn := rawMock(t, 0, func(string) bool { return false })
	defer closeFn()

	res, err := Probe(context.Background(), "http://"+addr+"/", Options{
		DelayThresholdMs: 200,
		ReadTimeoutMs:    2000,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Vulnerable {
		t.Errorf("clean server flagged as vulnerable: %+v", res.Findings)
	}
}

func TestProbeInvalidTarget(t *testing.T) {
	if _, err := Probe(context.Background(), "notaurl", Options{}); err == nil {
		t.Error("expected error for target without host")
	}
}
