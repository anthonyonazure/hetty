// Package tlsscan is a native (no-sslscan/testssl) TLS/SSL analyzer: it probes
// which protocol versions a host accepts, inspects the leaf certificate, and
// flags common weaknesses (expired/expiring/self-signed certs, deprecated
// protocols, weak keys/signatures, and weak ciphers).
package tlsscan

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"
)

// Options configures a TLS scan.
type Options struct {
	TimeoutMs  int    `json:"timeoutMs"`
	ServerName string `json:"serverName"` // SNI override (defaults to the host)
}

// CertInfo summarizes the leaf certificate.
type CertInfo struct {
	Subject            string   `json:"subject"`
	Issuer             string   `json:"issuer"`
	SANs               []string `json:"sans"`
	NotBefore          string   `json:"notBefore"`
	NotAfter           string   `json:"notAfter"`
	DaysUntilExpiry    int      `json:"daysUntilExpiry"`
	KeyType            string   `json:"keyType"`
	KeyBits            int      `json:"keyBits"`
	SignatureAlgorithm string   `json:"signatureAlgorithm"`
	SelfSigned         bool     `json:"selfSigned"`
}

// Result is the outcome of a TLS scan.
type Result struct {
	Host             string   `json:"host"`
	Protocols        []string `json:"protocols"`
	NegotiatedCipher string   `json:"negotiatedCipher"`
	Cert             CertInfo `json:"cert"`
	Issues           []string `json:"issues"`
}

var protocolVersions = []struct {
	name string
	ver  uint16
}{
	{"TLS 1.0", tls.VersionTLS10},
	{"TLS 1.1", tls.VersionTLS11},
	{"TLS 1.2", tls.VersionTLS12},
	{"TLS 1.3", tls.VersionTLS13},
}

// Scan analyzes the TLS configuration of host (host, host:port, or URL).
func Scan(ctx context.Context, host string, opts Options) (Result, error) {
	addr := normalizeAddr(host)
	serverName := opts.ServerName
	if serverName == "" {
		serverName, _, _ = net.SplitHostPort(addr)
	}

	timeout := time.Duration(opts.TimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	res := Result{Host: addr}

	var leaf *x509.Certificate
	var negotiatedState *tls.ConnectionState

	for _, pv := range protocolVersions {
		state, err := handshake(ctx, addr, serverName, timeout, &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // analysis, not trust
			MinVersion:         pv.ver,
			MaxVersion:         pv.ver,
			ServerName:         serverName,
		})
		if err != nil {
			continue
		}
		res.Protocols = append(res.Protocols, pv.name)
		negotiatedState = state
		if len(state.PeerCertificates) > 0 {
			leaf = state.PeerCertificates[0]
		}
	}

	if len(res.Protocols) == 0 {
		return res, fmt.Errorf("tlsscan: no TLS handshake succeeded with %s (is it serving TLS?)", addr)
	}

	if negotiatedState != nil {
		res.NegotiatedCipher = tls.CipherSuiteName(negotiatedState.CipherSuite)
	}
	if leaf != nil {
		res.Cert = certInfo(leaf)
	}

	res.Issues = findings(res, leaf, addr, serverName, timeout, ctx)
	return res, nil
}

func handshake(ctx context.Context, addr, serverName string, timeout time.Duration, cfg *tls.Config) (*tls.ConnectionState, error) {
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))
	tc := tls.Client(conn, cfg)
	if err := tc.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	state := tc.ConnectionState()
	return &state, nil
}

func certInfo(c *x509.Certificate) CertInfo {
	info := CertInfo{
		Subject:            c.Subject.CommonName,
		Issuer:             c.Issuer.CommonName,
		SANs:               c.DNSNames,
		NotBefore:          c.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:           c.NotAfter.UTC().Format(time.RFC3339),
		SignatureAlgorithm: c.SignatureAlgorithm.String(),
		SelfSigned:         c.Subject.String() == c.Issuer.String(),
	}
	info.DaysUntilExpiry = int(time.Until(c.NotAfter).Hours() / 24)

	switch pub := c.PublicKey.(type) {
	case *rsa.PublicKey:
		info.KeyType = "RSA"
		info.KeyBits = pub.N.BitLen()
	case *ecdsa.PublicKey:
		info.KeyType = "ECDSA"
		info.KeyBits = pub.Curve.Params().BitSize
	default:
		info.KeyType = "unknown"
	}
	return info
}

func findings(res Result, leaf *x509.Certificate, addr, serverName string, timeout time.Duration, ctx context.Context) []string {
	var issues []string

	for _, p := range res.Protocols {
		if p == "TLS 1.0" || p == "TLS 1.1" {
			issues = append(issues, "Deprecated protocol supported: "+p)
		}
	}

	if leaf != nil {
		if time.Now().After(leaf.NotAfter) {
			issues = append(issues, "Certificate is expired")
		} else if res.Cert.DaysUntilExpiry < 30 {
			issues = append(issues, fmt.Sprintf("Certificate expires soon (%d days)", res.Cert.DaysUntilExpiry))
		}
		if res.Cert.SelfSigned {
			issues = append(issues, "Certificate is self-signed")
		}
		if res.Cert.KeyType == "RSA" && res.Cert.KeyBits < 2048 {
			issues = append(issues, fmt.Sprintf("Weak RSA key (%d bits)", res.Cert.KeyBits))
		}
		if isWeakSignature(res.Cert.SignatureAlgorithm) {
			issues = append(issues, "Weak certificate signature ("+res.Cert.SignatureAlgorithm+")")
		}
	}

	if acceptsWeakCipher(ctx, addr, serverName, timeout) {
		issues = append(issues, "Weak cipher accepted (RC4/3DES)")
	}

	return issues
}

func isWeakSignature(sig string) bool {
	s := strings.ToUpper(sig)
	return strings.Contains(s, "MD5") || strings.Contains(s, "SHA1")
}

// acceptsWeakCipher checks whether the server completes a TLS 1.2 handshake when
// only known-weak ciphers (RC4, 3DES) are offered.
func acceptsWeakCipher(ctx context.Context, addr, serverName string, timeout time.Duration) bool {
	weak := []uint16{
		tls.TLS_RSA_WITH_RC4_128_SHA,
		tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
	}
	_, err := handshake(ctx, addr, serverName, timeout, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec
		MinVersion:         tls.VersionTLS10,
		MaxVersion:         tls.VersionTLS12,
		CipherSuites:       weak,
		ServerName:         serverName,
	})
	return err == nil
}

// normalizeAddr turns a host, URL, or host:port into host:port (default 443).
func normalizeAddr(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if _, _, err := net.SplitHostPort(s); err != nil {
		s = net.JoinHostPort(s, "443")
	}
	return s
}
