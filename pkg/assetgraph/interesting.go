package assetgraph

import (
	"sort"
	"strconv"
	"strings"
)

// interestingHostWords are substrings in a hostname that suggest a juicy,
// often-less-hardened target.
var interestingHostWords = []string{
	"dev", "staging", "stage", "test", "qa", "uat", "admin", "api", "internal",
	"intranet", "vpn", "jenkins", "grafana", "kibana", "gitlab", "jira",
	"prometheus", "sonar", "portainer", "phpmyadmin", "backup", "old", "beta",
	"demo", "sandbox", "mgmt", "manage", "dashboard", "git", "ci", "registry",
}

// interestingPorts are services that are high-value when exposed.
var interestingPorts = map[int]string{
	3306: "MySQL", 5432: "PostgreSQL", 27017: "MongoDB", 6379: "Redis",
	9200: "Elasticsearch", 11211: "Memcached", 1433: "MS-SQL", 5984: "CouchDB",
	10000: "Webmin", 2375: "Docker API", 2376: "Docker API", 3389: "RDP",
	5900: "VNC", 9092: "Kafka", 2181: "ZooKeeper", 5601: "Kibana",
	8086: "InfluxDB", 15672: "RabbitMQ mgmt", 6443: "Kubernetes API",
	9000: "admin / SonarQube", 8443: "admin HTTPS", 8080: "admin / proxy",
	7001: "WebLogic", 50000: "SAP",
}

// InterestingReasons returns why an asset is noteworthy (empty if it isn't).
func InterestingReasons(a *Asset) []string {
	var reasons []string
	switch a.Kind {
	case KindHost:
		lower := strings.ToLower(a.Value)
		for _, w := range interestingHostWords {
			if strings.Contains(lower, w+".") || strings.Contains(lower, "."+w) ||
				strings.Contains(lower, w+"-") || strings.Contains(lower, "-"+w) {
				reasons = append(reasons, "hostname suggests "+w)
				break
			}
		}
	case KindService:
		if i := strings.LastIndex(a.Value, ":"); i >= 0 {
			if port, err := strconv.Atoi(a.Value[i+1:]); err == nil {
				if name, ok := interestingPorts[port]; ok {
					reasons = append(reasons, "exposed "+name+" (:"+strconv.Itoa(port)+")")
				}
			}
		}
	case KindFinding:
		if sev := a.Attrs["severity"]; sev == "high" || sev == "critical" {
			reasons = append(reasons, sev+"-severity finding")
		}
	}
	return reasons
}

// Interesting is an asset flagged by the heuristics, with reasons.
type Interesting struct {
	*Asset
	Reasons []string `json:"reasons"`
}

// Interesting returns the noteworthy assets — the ones worth looking at first.
func (g *Graph) Interesting() []Interesting {
	g.mu.RLock()
	defer g.mu.RUnlock()
	var out []Interesting
	for _, a := range g.assets {
		if r := InterestingReasons(a); len(r) > 0 {
			out = append(out, Interesting{Asset: a, Reasons: r})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Value < out[j].Value })
	return out
}
