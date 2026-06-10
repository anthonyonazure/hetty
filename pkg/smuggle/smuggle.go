// Package smuggle implements a timing-based HTTP request smuggling probe —
// Hetty's analogue of Burp's "HTTP Request Smuggler". It sends raw requests with
// deliberately conflicting Content-Length and Transfer-Encoding headers (which a
// normal HTTP client refuses to construct) and infers a front-end/back-end
// desync from a response-time anomaly: a vulnerable back-end blocks waiting for
// body bytes that never arrive, so the crafted request hangs while a normal one
// returns immediately.
//
// The probe is non-destructive (it only measures timing) but, like all active
// testing, must only be run against authorized targets.
package smuggle

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

// Technique identifies which desync variant was detected.
type Technique string

const (
	CLTE Technique = "CL.TE"
	TECL Technique = "TE.CL"
)

// Options configures a probe.
type Options struct {
	// DelayThresholdMs is how much slower than the baseline a crafted request
	// must be to count as a hang (default 5000ms).
	DelayThresholdMs int `json:"delayThresholdMs"`
	// ReadTimeoutMs bounds how long a crafted request may hang (default 8000ms).
	ReadTimeoutMs int `json:"readTimeoutMs"`
}

// Finding is one detected technique.
type Finding struct {
	Technique  Technique `json:"technique"`
	BaselineMs int64     `json:"baselineMs"`
	ProbeMs    int64     `json:"probeMs"`
	TimedOut   bool      `json:"timedOut"`
	Detail     string    `json:"detail"`
}

// Result is the probe outcome.
type Result struct {
	Target     string    `json:"target"`
	Vulnerable bool      `json:"vulnerable"`
	BaselineMs int64     `json:"baselineMs"`
	Findings   []Finding `json:"findings"`
	Note       string    `json:"note"`
}

// Probe runs the CL.TE and TE.CL timing tests against target.
func Probe(ctx context.Context, target string, opts Options) (Result, error) {
	u, err := url.Parse(target)
	if err != nil || u.Host == "" {
		return Result{}, fmt.Errorf("smuggle: target must be an absolute URL")
	}

	delayThreshold := time.Duration(opts.DelayThresholdMs) * time.Millisecond
	if delayThreshold <= 0 {
		delayThreshold = 5 * time.Second
	}
	readTimeout := time.Duration(opts.ReadTimeoutMs) * time.Millisecond
	if readTimeout <= 0 {
		readTimeout = 8 * time.Second
	}

	host := u.Host
	path := u.RequestURI()
	if path == "" {
		path = "/"
	}
	useTLS := u.Scheme == "https"

	result := Result{Target: target}

	// Baseline: a normal, well-formed request.
	baseElapsed, _, err := sendRaw(ctx, host, useTLS, normalRequest(host, path), readTimeout)
	if err != nil {
		return Result{}, fmt.Errorf("smuggle: baseline request failed: %w", err)
	}
	result.BaselineMs = baseElapsed.Milliseconds()

	for _, tc := range []struct {
		tech Technique
		raw  string
	}{
		{CLTE, clteRequest(host, path)},
		{TECL, teclRequest(host, path)},
	} {
		elapsed, timedOut, err := sendRaw(ctx, host, useTLS, tc.raw, readTimeout)
		f := Finding{
			Technique:  tc.tech,
			BaselineMs: baseElapsed.Milliseconds(),
			ProbeMs:    elapsed.Milliseconds(),
			TimedOut:   timedOut,
		}
		if err != nil && !timedOut {
			f.Detail = "probe error: " + err.Error()
			result.Findings = append(result.Findings, f)
			continue
		}

		if elapsed-baseElapsed >= delayThreshold {
			f.Detail = fmt.Sprintf("crafted request was %dms slower than baseline — likely %s desync",
				(elapsed - baseElapsed).Milliseconds(), tc.tech)
			result.Vulnerable = true
		} else {
			f.Detail = "no significant delay"
		}
		result.Findings = append(result.Findings, f)
	}

	if result.Vulnerable {
		result.Note = "Timing anomaly detected. Confirm manually before reporting — timing probes can false-positive on slow or rate-limited hosts."
	} else {
		result.Note = "No desync timing anomaly observed."
	}

	return result, nil
}

// normalRequest is a well-formed baseline request.
func normalRequest(host, path string) string {
	return "POST " + path + " HTTP/1.1\r\n" +
		"Host: " + host + "\r\n" +
		"Content-Type: application/x-www-form-urlencoded\r\n" +
		"Content-Length: 0\r\n" +
		"Connection: close\r\n" +
		"\r\n"
}

// clteRequest detects CL.TE: front-end honors Content-Length, back-end honors
// Transfer-Encoding. With CL=4 the front-end forwards "1\r\nA\r\n"; a chunked
// back-end reads chunk size 1, byte A, then blocks awaiting the next chunk.
func clteRequest(host, path string) string {
	return "POST " + path + " HTTP/1.1\r\n" +
		"Host: " + host + "\r\n" +
		"Content-Type: application/x-www-form-urlencoded\r\n" +
		"Transfer-Encoding: chunked\r\n" +
		"Content-Length: 4\r\n" +
		"\r\n" +
		"1\r\n" +
		"A\r\n" +
		"X"
}

// teclRequest detects TE.CL: front-end honors Transfer-Encoding (sees the 0
// terminator and forwards "0\r\n\r\n"), back-end honors Content-Length=6 and
// blocks waiting for 6 body bytes it never receives.
func teclRequest(host, path string) string {
	return "POST " + path + " HTTP/1.1\r\n" +
		"Host: " + host + "\r\n" +
		"Content-Type: application/x-www-form-urlencoded\r\n" +
		"Transfer-Encoding: chunked\r\n" +
		"Content-Length: 6\r\n" +
		"\r\n" +
		"0\r\n" +
		"\r\n" +
		"X"
}

// sendRaw opens a connection, writes raw bytes, and waits for the first response
// byte. It returns the elapsed time, whether the read timed out (the hang
// signal), and any non-timeout error.
func sendRaw(ctx context.Context, host string, useTLS bool, raw string, readTimeout time.Duration) (time.Duration, bool, error) {
	if !strings.Contains(host, ":") {
		if useTLS {
			host += ":443"
		} else {
			host += ":80"
		}
	}

	dialer := &net.Dialer{Timeout: 10 * time.Second}

	var conn net.Conn
	var err error
	if useTLS {
		//nolint:gosec
		conn, err = tls.DialWithDialer(dialer, "tcp", host, &tls.Config{InsecureSkipVerify: true})
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", host)
	}
	if err != nil {
		return 0, false, err
	}
	defer conn.Close()

	start := time.Now()
	_ = conn.SetDeadline(start.Add(readTimeout))

	if _, err := conn.Write([]byte(raw)); err != nil {
		return time.Since(start), false, err
	}

	// Wait for the first byte of a response.
	reader := bufio.NewReader(conn)
	_, err = reader.ReadByte()
	elapsed := time.Since(start)

	if err != nil {
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			return elapsed, true, nil
		}
		return elapsed, false, err
	}

	return elapsed, false, nil
}
