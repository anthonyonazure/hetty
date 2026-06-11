package asm

import (
	"context"
	"fmt"
	"testing"
)

func fakeToolbox() Toolbox {
	return Toolbox{
		Subdomains: func(_ context.Context, domain string) ([]string, error) {
			return []string{"www." + domain, "api." + domain}, nil
		},
		Fingerprint: func(_ context.Context, _ string) (Tech, error) {
			return Tech{Server: "nginx", Technologies: []string{"nginx", "PHP"}}, nil
		},
		PortScan: func(_ context.Context, _ string, full bool) ([]Port, error) {
			ports := []Port{{Port: 21, Service: "ftp", Banner: "vsftpd 2.3.4"}}
			if full {
				ports = append(ports, Port{Port: 8080, Service: "http-proxy"})
			}
			return ports, nil
		},
		TLSScan: func(_ context.Context, _ string) (*TLSSummary, error) {
			return &TLSSummary{Protocols: []string{"TLS 1.2"}, Issues: []string{"self-signed"}}, nil
		},
		WAFDetect: func(_ context.Context, _ string) ([]string, error) {
			return []string{"Cloudflare"}, nil
		},
		WebScan: func(_ context.Context, _ string) ([]Finding, error) {
			return []Finding{{Source: "scanner", Title: "Reflected XSS", Severity: "high"}}, nil
		},
		Screenshot: func(_ context.Context, _ string) (string, error) {
			return "BASE64PNG", nil
		},
		VulnMatch: func(banner string) []Vuln {
			if banner == "vsftpd 2.3.4" {
				return []Vuln{{CVE: "CVE-2011-2523", Title: "vsftpd backdoor", Severity: "critical", ExploitAvailable: true, MSFModule: "exploit/unix/ftp/vsftpd_234_backdoor"}}
			}
			return nil
		},
		Exploit: func(_ context.Context, module string, opts map[string]interface{}) (string, error) {
			return fmt.Sprintf("launched %s against %v", module, opts["RHOSTS"]), nil
		},
	}
}

func TestRunFullMode(t *testing.T) {
	ws := &Workspace{Name: "test", Targets: []string{"example.com"}}
	eng := New(fakeToolbox())

	sum := eng.Run(context.Background(), ws, ModeFull, RunOptions{FullPortScan: true, Screenshot: true})

	if sum.HostsScanned != 1 {
		t.Fatalf("hostsScanned = %d", sum.HostsScanned)
	}
	if len(ws.Hosts) != 1 {
		t.Fatalf("expected 1 host, got %d", len(ws.Hosts))
	}
	h := ws.Hosts[0]
	if h.Host != "example.com" {
		t.Errorf("host = %q", h.Host)
	}
	if len(h.Ports) != 2 {
		t.Errorf("expected 2 ports (full scan), got %d", len(h.Ports))
	}
	if h.Tech == nil || h.Tech.Server != "nginx" {
		t.Errorf("fingerprint not populated: %+v", h.Tech)
	}
	if len(h.WAF) == 0 || h.WAF[0] != "Cloudflare" {
		t.Errorf("WAF not populated: %v", h.WAF)
	}
	if h.TLS == nil {
		t.Errorf("TLS not populated")
	}
	if len(h.Findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(h.Findings))
	}
	if h.Screenshot != "BASE64PNG" {
		t.Errorf("screenshot not captured")
	}
	if len(ws.Subdomains) != 2 {
		t.Errorf("expected 2 subdomains, got %v", ws.Subdomains)
	}
	// vuln matched on the ftp banner.
	if len(h.Ports[0].Vulns) != 1 || h.Ports[0].Vulns[0].CVE != "CVE-2011-2523" {
		t.Errorf("vuln not matched: %+v", h.Ports[0].Vulns)
	}
	// Full mode without AllowExploit must NOT exploit.
	if sum.Exploited != 0 || len(h.Exploits) != 0 {
		t.Errorf("should not exploit without AllowExploit")
	}
}

func TestRunNukeGate(t *testing.T) {
	ws := &Workspace{Name: "nuke", Targets: []string{"10.0.0.5"}}
	eng := New(fakeToolbox())

	// Without AllowExploit: no exploitation.
	sum := eng.Run(context.Background(), ws, ModeNuke, RunOptions{})
	if sum.Exploited != 0 {
		t.Fatalf("nuke without AllowExploit should not exploit, got %d", sum.Exploited)
	}

	// With AllowExploit: the matched vsftpd vuln is exploited.
	ws2 := &Workspace{Name: "nuke2", Targets: []string{"10.0.0.5"}}
	sum = eng.Run(context.Background(), ws2, ModeNuke, RunOptions{AllowExploit: true})
	if sum.Exploited != 1 {
		t.Fatalf("expected 1 exploitation, got %d", sum.Exploited)
	}
	h := ws2.Hosts[0]
	if len(h.Exploits) != 1 || h.Exploits[0].Status != "attempted" {
		t.Fatalf("exploit result missing: %+v", h.Exploits)
	}
}

func TestRunIPSkipsSubdomains(t *testing.T) {
	ws := &Workspace{Name: "ip", Targets: []string{"10.0.0.1"}}
	eng := New(fakeToolbox())
	eng.Run(context.Background(), ws, ModeRecon, RunOptions{})
	if len(ws.Subdomains) != 0 {
		t.Errorf("IP target should not enumerate subdomains, got %v", ws.Subdomains)
	}
}

func TestStoreSnapshotRestore(t *testing.T) {
	s := NewStore()
	s.Save(&Workspace{Name: "w1", Targets: []string{"a.com"}, Hosts: []*Host{{Host: "a.com"}}})
	blob, err := s.Snapshot()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	s2 := NewStore()
	if err := s2.Restore(blob); err != nil {
		t.Fatalf("restore: %v", err)
	}
	w, ok := s2.Get("w1")
	if !ok || len(w.Hosts) != 1 {
		t.Fatalf("workspace not restored: %+v", w)
	}
}
