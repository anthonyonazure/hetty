// Package portscan is a native (no-nmap) TCP connect scanner with banner
// grabbing and service identification, providing the network-discovery layer
// for Hetty's Sn1per-style attack-surface scanning.
package portscan

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// Options configures a scan.
type Options struct {
	// Ports to scan. When empty, the top-N common ports are used.
	Ports []int `json:"ports"`
	// TopPorts selects the N most common ports when Ports is empty (default 100).
	TopPorts int `json:"topPorts"`
	// Concurrency caps simultaneous connections (default 100).
	Concurrency int `json:"concurrency"`
	// TimeoutMs is the per-connection dial/read timeout (default 1500).
	TimeoutMs int `json:"timeoutMs"`
	// Banner enables banner grabbing on open ports.
	Banner bool `json:"banner"`
}

// Port is a single open port result.
type Port struct {
	Port    int    `json:"port"`
	State   string `json:"state"`
	Service string `json:"service"`
	Banner  string `json:"banner,omitempty"`
}

// Result is the outcome of a host scan.
type Result struct {
	Host    string `json:"host"`
	Open    []Port `json:"open"`
	Scanned int    `json:"scanned"`
}

// Scan performs a TCP connect scan of host (hostname or IP).
func Scan(ctx context.Context, host string, opts Options) (Result, error) {
	host = strings.TrimSpace(host)
	if host == "" {
		return Result{}, fmt.Errorf("portscan: host is required")
	}
	// Accept a URL or host:port and reduce to the bare host.
	host = bareHost(host)

	ports := opts.Ports
	if len(ports) == 0 {
		n := opts.TopPorts
		if n <= 0 {
			n = 100
		}
		ports = TopPorts(n)
	}

	concurrency := opts.Concurrency
	if concurrency <= 0 {
		concurrency = 100
	}
	timeout := time.Duration(opts.TimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 1500 * time.Millisecond
	}

	var (
		mu   sync.Mutex
		open []Port
		wg   sync.WaitGroup
		sem  = make(chan struct{}, concurrency)
	)

	for _, p := range ports {
		select {
		case <-ctx.Done():
			return Result{Host: host, Open: sortPorts(open), Scanned: len(ports)}, ctx.Err()
		default:
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(port int) {
			defer wg.Done()
			defer func() { <-sem }()

			if pr, ok := scanPort(ctx, host, port, timeout, opts.Banner); ok {
				mu.Lock()
				open = append(open, pr)
				mu.Unlock()
			}
		}(p)
	}

	wg.Wait()

	return Result{Host: host, Open: sortPorts(open), Scanned: len(ports)}, nil
}

func scanPort(ctx context.Context, host string, port int, timeout time.Duration, banner bool) (Port, bool) {
	addr := net.JoinHostPort(host, fmt.Sprint(port))
	d := net.Dialer{Timeout: timeout}

	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return Port{}, false
	}
	defer conn.Close()

	pr := Port{Port: port, State: "open", Service: ServiceName(port)}

	if banner {
		pr.Banner = grabBanner(conn, port, timeout)
	}

	return pr, true
}

// grabBanner first reads any banner the service volunteers (SSH/FTP/SMTP send
// one immediately); if the service stays silent it sends a minimal HTTP request
// and reads the reply, so HTTP on non-standard ports is still fingerprinted.
func grabBanner(conn net.Conn, port int, timeout time.Duration) string {
	buf := make([]byte, 512)

	firstWait := 700 * time.Millisecond
	if timeout < firstWait {
		firstWait = timeout
	}
	_ = conn.SetReadDeadline(time.Now().Add(firstWait))
	if n, _ := conn.Read(buf); n > 0 {
		return sanitizeBanner(buf[:n])
	}

	// Silent so far — probe with an HTTP request.
	_ = conn.SetWriteDeadline(time.Now().Add(timeout))
	if _, err := conn.Write([]byte("GET / HTTP/1.0\r\nHost: scan\r\n\r\n")); err != nil {
		return ""
	}
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	if n, _ := conn.Read(buf); n > 0 {
		return sanitizeBanner(buf[:n])
	}
	return ""
}

func sanitizeBanner(b []byte) string {
	// Keep the first non-empty line, printable characters only.
	line := b
	if i := indexNL(b); i >= 0 {
		line = b[:i]
	}
	var sb strings.Builder
	for _, c := range line {
		if c >= 0x20 && c < 0x7f {
			sb.WriteByte(c)
		}
	}
	return strings.TrimSpace(sb.String())
}

func indexNL(b []byte) int {
	for i, c := range b {
		if c == '\n' || c == '\r' {
			return i
		}
	}
	return -1
}

func sortPorts(ports []Port) []Port {
	sort.Slice(ports, func(i, j int) bool { return ports[i].Port < ports[j].Port })
	return ports
}

// bareHost reduces a URL or host:port to the bare host.
func bareHost(s string) string {
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if h, _, err := net.SplitHostPort(s); err == nil {
		return h
	}
	return s
}
