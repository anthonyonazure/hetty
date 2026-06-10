package collab

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestDNSServerRecordsLookup(t *testing.T) {
	srv := NewServer("http://localhost/oob")
	srv.SetDNSDomain("oob.example.com")

	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.ServeDNS(ctx, conn, net.IPv4(127, 0, 0, 1)) }()

	// Build a minimal A query for "deadbeef.oob.example.com".
	token := "deadbeef"
	query := buildQuery(token + ".oob.example.com")

	client, err := net.Dial("udp", conn.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	if _, err := client.Write(query); err != nil {
		t.Fatal(err)
	}

	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	resp := make([]byte, 512)
	n, err := client.Read(resp)
	if err != nil {
		t.Fatalf("no DNS response: %v", err)
	}
	if n < dnsHeaderLen {
		t.Fatalf("short DNS response: %d bytes", n)
	}
	// QR bit set.
	if resp[2]&0x80 == 0 {
		t.Error("response QR bit not set")
	}

	// Interaction recorded against the token.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if srv.InteractionCount(token) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := srv.InteractionCount(token); got != 1 {
		t.Fatalf("InteractionCount = %d, want 1", got)
	}
	inter := srv.Interactions(token)
	if inter[0].Protocol != "dns" {
		t.Errorf("protocol = %q, want dns", inter[0].Protocol)
	}
	if inter[0].Host != "deadbeef.oob.example.com" {
		t.Errorf("host = %q", inter[0].Host)
	}
}

func TestDNSHost(t *testing.T) {
	srv := NewServer("http://localhost/oob")
	if srv.DNSHost("tok") != "" {
		t.Error("DNSHost should be empty with no domain")
	}
	srv.SetDNSDomain("oob.example.com")
	if got := srv.DNSHost("tok"); got != "tok.oob.example.com" {
		t.Errorf("DNSHost = %q", got)
	}
}

func TestParseQuestion(t *testing.T) {
	q := buildQuery("abc.example.com")
	name, qtype, err := parseQuestion(q)
	if err != nil {
		t.Fatal(err)
	}
	if name != "abc.example.com" {
		t.Errorf("name = %q", name)
	}
	if qtype != qtypeA {
		t.Errorf("qtype = %d, want %d", qtype, qtypeA)
	}
}

// buildQuery constructs a minimal DNS A query for name.
func buildQuery(name string) []byte {
	msg := []byte{
		0x12, 0x34, // ID
		0x01, 0x00, // flags: RD
		0x00, 0x01, // QDCOUNT
		0x00, 0x00, // ANCOUNT
		0x00, 0x00, // NSCOUNT
		0x00, 0x00, // ARCOUNT
	}
	for _, label := range splitLabels(name) {
		msg = append(msg, byte(len(label)))
		msg = append(msg, []byte(label)...)
	}
	msg = append(msg, 0x00)       // end of name
	msg = append(msg, 0x00, 0x01) // QTYPE A
	msg = append(msg, 0x00, 0x01) // QCLASS IN
	return msg
}

func splitLabels(name string) []string {
	var labels []string
	cur := ""
	for _, r := range name {
		if r == '.' {
			labels = append(labels, cur)
			cur = ""
			continue
		}
		cur += string(r)
	}
	if cur != "" {
		labels = append(labels, cur)
	}
	return labels
}
