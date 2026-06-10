package collab

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"time"
)

// DNS support extends the collaborator with an out-of-band DNS channel. Many
// blind vulnerabilities (SSRF, XXE, some SQLi/command-injection contexts) cause
// the target to resolve a hostname but never make an HTTP request — a DNS
// pingback is the only signal. When a DNS domain is configured and delegated to
// Hetty's listener, a lookup of "<token>.<domain>" is recorded against that
// token, so it counts toward the same interaction total the scanner polls.

// SetDNSDomain configures the base domain served by the DNS listener (e.g.
// "oob.example.com"). Tokens are issued as "<token>.<domain>".
func (s *Server) SetDNSDomain(domain string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dnsDomain = strings.Trim(strings.TrimSpace(domain), ".")
}

// DNSDomain returns the configured DNS base domain (may be empty).
func (s *Server) DNSDomain() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dnsDomain
}

// DNSHost returns the DNS payload host for a token, or "" if no DNS domain is
// configured.
func (s *Server) DNSHost(token string) string {
	d := s.DNSDomain()
	if d == "" {
		return ""
	}
	return token + "." + d
}

// recordDNS stores a DNS interaction. The token is the leading label of the
// queried name.
func (s *Server) recordDNS(qname, remoteAddr string) {
	token := qname
	if i := strings.IndexByte(qname, '.'); i >= 0 {
		token = qname[:i]
	}
	if token == "" {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.seq++
	interaction := Interaction{
		ID:         hexSeq(s.seq),
		Token:      token,
		Protocol:   "dns",
		RemoteAddr: remoteAddr,
		Host:       qname,
		Path:       qname,
		Time:       time.Now().UTC(),
	}
	s.interactions[token] = append(s.interactions[token], interaction)
}

// ServeDNS reads DNS queries from conn and records them until the context is
// cancelled or the connection is closed. Replies to A queries with answerIP
// (defaulting to 127.0.0.1); other query types receive an empty answer. It
// implements just enough of RFC 1035 to capture the queried name and respond —
// no zone files, no recursion.
func (s *Server) ServeDNS(ctx context.Context, conn net.PacketConn, answerIP net.IP) error {
	if answerIP == nil {
		answerIP = net.IPv4(127, 0, 0, 1)
	}
	answerIP = answerIP.To4()

	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()

	buf := make([]byte, 512)
	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}

		req := make([]byte, n)
		copy(req, buf[:n])

		qname, qtype, err := parseQuestion(req)
		if err != nil {
			continue
		}

		s.recordDNS(strings.TrimSuffix(strings.ToLower(qname), "."), addr.String())

		resp := buildDNSResponse(req, qtype, answerIP)
		if resp != nil {
			_, _ = conn.WriteTo(resp, addr)
		}
	}
}

const (
	dnsHeaderLen = 12
	qtypeA       = 1
)

var errMalformedDNS = errors.New("collab: malformed DNS message")

// parseQuestion extracts the first question's name and type. Question names do
// not use message compression, so a straight label walk is sufficient.
func parseQuestion(msg []byte) (qname string, qtype uint16, err error) {
	if len(msg) < dnsHeaderLen {
		return "", 0, errMalformedDNS
	}
	if binary.BigEndian.Uint16(msg[4:6]) < 1 {
		return "", 0, errMalformedDNS
	}

	off := dnsHeaderLen
	var labels []string
	for {
		if off >= len(msg) {
			return "", 0, errMalformedDNS
		}
		l := int(msg[off])
		off++
		if l == 0 {
			break
		}
		if l&0xC0 != 0 { // compression pointer not expected in questions
			return "", 0, errMalformedDNS
		}
		if off+l > len(msg) {
			return "", 0, errMalformedDNS
		}
		labels = append(labels, string(msg[off:off+l]))
		off += l
	}

	if off+4 > len(msg) {
		return "", 0, errMalformedDNS
	}
	qtype = binary.BigEndian.Uint16(msg[off : off+2])

	return strings.Join(labels, "."), qtype, nil
}

// buildDNSResponse echoes the query header and question and, for A queries,
// appends a single A answer pointing at ip.
func buildDNSResponse(req []byte, qtype uint16, ip net.IP) []byte {
	if len(req) < dnsHeaderLen {
		return nil
	}

	// Find the end of the question section (name + qtype + qclass).
	off := dnsHeaderLen
	for off < len(req) {
		l := int(req[off])
		off++
		if l == 0 {
			break
		}
		if l&0xC0 != 0 || off+l > len(req) {
			return nil
		}
		off += l
	}
	off += 4 // qtype + qclass
	if off > len(req) {
		return nil
	}

	question := req[dnsHeaderLen:off]

	resp := make([]byte, 0, off+16)
	// Header: copy ID.
	resp = append(resp, req[0], req[1])
	// Flags: QR=1, AA=1, RD copied, RA=1, RCODE=0 => 0x8580 with RD bit echoed.
	flags := uint16(0x8580)
	if req[2]&0x01 != 0 {
		flags |= 0x0100
	}
	resp = appendUint16(resp, flags)
	resp = appendUint16(resp, 1) // QDCOUNT

	answers := uint16(0)
	if qtype == qtypeA && ip != nil {
		answers = 1
	}
	resp = appendUint16(resp, answers) // ANCOUNT
	resp = appendUint16(resp, 0)       // NSCOUNT
	resp = appendUint16(resp, 0)       // ARCOUNT

	resp = append(resp, question...)

	if answers == 1 {
		resp = append(resp, 0xC0, 0x0C) // name pointer to offset 12
		resp = appendUint16(resp, qtypeA)
		resp = appendUint16(resp, 1) // class IN
		resp = appendUint32(resp, 60) // TTL
		resp = appendUint16(resp, 4)  // RDLENGTH
		resp = append(resp, ip...)
	}

	return resp
}

func appendUint16(b []byte, v uint16) []byte {
	return append(b, byte(v>>8), byte(v))
}

func appendUint32(b []byte, v uint32) []byte {
	return append(b, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func hexSeq(seq uint64) string {
	const hexdigits = "0123456789abcdef"
	var out [6]byte
	for i := 0; i < 6; i++ {
		out[5-i] = hexdigits[(seq>>(uint(i)*4))&0xF]
	}
	return string(out[:])
}
