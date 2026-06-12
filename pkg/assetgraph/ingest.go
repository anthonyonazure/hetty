package assetgraph

import (
	"fmt"
	"strings"
)

func keyDomain(d string) string             { return "domain:" + d }
func keyHost(h string) string               { return "host:" + h }
func keyURL(u string) string                { return "url:" + u }
func keyService(host string, port int) string { return fmt.Sprintf("service:%s:%d", host, port) }
func keyFinding(host, dedup string) string  { return "finding:" + host + ":" + dedup }

// IngestSubdomain records a domain and one of its subdomains (host), linking the
// host to its parent domain.
func (g *Graph) IngestSubdomain(domain, host, source, now string) {
	g.Upsert(Asset{Key: keyDomain(domain), Kind: KindDomain, Value: domain, Sources: []string{source}}, now)
	g.Upsert(Asset{Key: keyHost(host), Kind: KindHost, Value: host, Sources: []string{source}, Parents: []string{keyDomain(domain)}}, now)
}

// IngestHost records a bare host/IP.
func (g *Graph) IngestHost(host, source, now string) {
	g.Upsert(Asset{Key: keyHost(host), Kind: KindHost, Value: host, Sources: []string{source}}, now)
}

// IngestService records an open service on a host (auto-creating the host).
func (g *Graph) IngestService(host string, port int, service, banner, source, now string) {
	g.IngestHost(host, source, now)
	attrs := map[string]string{"service": service}
	if banner != "" {
		attrs["banner"] = banner
	}
	g.Upsert(Asset{
		Key: keyService(host, port), Kind: KindService, Value: fmt.Sprintf("%s:%d", host, port),
		Sources: []string{source}, Attrs: attrs, Parents: []string{keyHost(host)},
	}, now)
}

// IngestURL records a URL (and its tech stack) under a host.
func (g *Graph) IngestURL(host, url string, techs []string, source, now string) {
	g.IngestHost(host, source, now)
	attrs := map[string]string{}
	if len(techs) > 0 {
		attrs["technologies"] = strings.Join(techs, ", ")
	}
	g.Upsert(Asset{
		Key: keyURL(url), Kind: KindURL, Value: url,
		Sources: []string{source}, Attrs: attrs, Parents: []string{keyHost(host)},
	}, now)
}

// IngestFinding records a finding against a host (auto-creating the host).
func (g *Graph) IngestFinding(host, title, severity, source, now string) {
	g.IngestHost(host, source, now)
	g.Upsert(Asset{
		Key: keyFinding(host, title), Kind: KindFinding, Value: title,
		Sources: []string{source}, Attrs: map[string]string{"severity": severity},
		Parents: []string{keyHost(host)},
	}, now)
}
