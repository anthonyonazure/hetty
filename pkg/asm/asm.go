// Package asm is Hetty's attack-surface-management layer: a persistent
// workspace model plus a scan-mode orchestrator that chains the recon, port,
// TLS, WAF, web-scan, screenshot, vuln-match and (optionally) Metasploit
// engines into one-command sweeps — the Sn1per-style core of Hetty.
package asm

import (
	"encoding/json"
	"sort"
	"sync"
)

// Tech is a host's fingerprinted technology stack.
type Tech struct {
	Server       string   `json:"server,omitempty"`
	Powered      string   `json:"powered,omitempty"`
	Title        string   `json:"title,omitempty"`
	Technologies []string `json:"technologies,omitempty"`
}

// Vuln is a known vulnerability matched to a service.
type Vuln struct {
	CVE              string `json:"cve"`
	Title            string `json:"title"`
	Severity         string `json:"severity"`
	ExploitAvailable bool   `json:"exploitAvailable"`
	MSFModule        string `json:"msfModule,omitempty"`
}

// Port is an open port plus any matched vulns.
type Port struct {
	Port    int    `json:"port"`
	Service string `json:"service"`
	Banner  string `json:"banner,omitempty"`
	Vulns   []Vuln `json:"vulns,omitempty"`
}

// TLSSummary condenses a TLS scan.
type TLSSummary struct {
	Protocols       []string `json:"protocols"`
	CertSubject     string   `json:"certSubject"`
	DaysUntilExpiry int      `json:"daysUntilExpiry"`
	Issues          []string `json:"issues,omitempty"`
}

// Finding is a web/vuln finding.
type Finding struct {
	Source   string `json:"source"`
	Title    string `json:"title"`
	Severity string `json:"severity"`
	Detail   string `json:"detail,omitempty"`
}

// ExploitResult records a Metasploit auto-exploitation attempt.
type ExploitResult struct {
	Module string `json:"module"`
	Target string `json:"target"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// Host is everything known about one target host.
type Host struct {
	Host       string          `json:"host"`
	Ports      []Port          `json:"ports,omitempty"`
	Tech       *Tech           `json:"tech,omitempty"`
	WAF        []string        `json:"waf,omitempty"`
	TLS        *TLSSummary     `json:"tls,omitempty"`
	Screenshot string          `json:"screenshot,omitempty"` // base64 PNG
	Findings   []Finding       `json:"findings,omitempty"`
	Exploits   []ExploitResult `json:"exploits,omitempty"`
}

// Workspace is an attack-surface workspace.
type Workspace struct {
	Name       string   `json:"name"`
	Targets    []string `json:"targets"`
	Subdomains []string `json:"subdomains,omitempty"`
	Hosts      []*Host  `json:"hosts"`
	CreatedAt  string   `json:"createdAt"`
	UpdatedAt  string   `json:"updatedAt"`
	LastMode   string   `json:"lastMode,omitempty"`
}

// host returns the Host entry for name, creating it if absent.
func (w *Workspace) host(name string) *Host {
	for _, h := range w.Hosts {
		if h.Host == name {
			return h
		}
	}
	h := &Host{Host: name}
	w.Hosts = append(w.Hosts, h)
	return h
}

// Store holds workspaces and persists them via Snapshot/Restore.
type Store struct {
	mu         sync.RWMutex
	workspaces map[string]*Workspace
}

// NewStore returns an empty workspace store.
func NewStore() *Store {
	return &Store{workspaces: map[string]*Workspace{}}
}

// Save inserts or replaces a workspace.
func (s *Store) Save(w *Workspace) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.workspaces[w.Name] = w
}

// Get returns a workspace by name.
func (s *Store) Get(name string) (*Workspace, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	w, ok := s.workspaces[name]
	return w, ok
}

// List returns all workspaces sorted by name.
func (s *Store) List() []*Workspace {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Workspace, 0, len(s.workspaces))
	for _, w := range s.workspaces {
		out = append(out, w)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Delete removes a workspace.
func (s *Store) Delete(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.workspaces, name)
}

// Snapshot serializes all workspaces.
func (s *Store) Snapshot() ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return json.Marshal(s.workspaces)
}

// Restore replaces store contents from a snapshot.
func (s *Store) Restore(data []byte) error {
	var m map[string]*Workspace
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}
	if m == nil {
		m = map[string]*Workspace{}
	}
	s.mu.Lock()
	s.workspaces = m
	s.mu.Unlock()
	return nil
}
